package org.kvxd.source2offset.engine

import org.kvxd.source2offset.core.MemReader
import org.kvxd.source2offset.core.Module
import org.kvxd.source2offset.elf.ElfParser
import org.kvxd.source2offset.engine.rtti.RttiInspector
import org.kvxd.source2offset.export.InterfaceEntry
import org.kvxd.source2offset.export.OffsetEntry
import org.kvxd.source2offset.export.RuntimeRootEntry
import org.kvxd.source2offset.export.normaliseModuleName

data class OffsetDiscoveryResult(
    val offsets: Map<String, List<OffsetEntry>>,
)

@Suppress("UNUSED_PARAMETER")
class NativeOffsetDumper(
    private val mem: MemReader,
    private val modules: List<Module>,
    private val rtti: RttiInspector,
    private val readFile: (String) -> ByteArray,
) {
    private val entries = mutableListOf<OffsetEntry>()

    fun dump(
        interfaces: List<InterfaceEntry>,
        runtimeRoots: List<RuntimeRootEntry>,
        log: (String) -> Unit = {},
    ): OffsetDiscoveryResult {
        log("Dumping raw offsets...")

        globalRules.forEach { resolveGlobal(it, log) }
        resolveButtons(log)
        memberRules.forEach { resolveMember(it, log) }

        val grouped = entries
            .groupBy { normaliseModuleName(it.moduleName) }
            .mapValues { (_, values) -> values.sortedBy { it.name } }

        return OffsetDiscoveryResult(grouped)
    }

    private fun resolveGlobal(rule: GlobalRule, log: (String) -> Unit) {
        val module = modules.firstOrNull { it.name == rule.moduleName } ?: return
        val image = runCatching { readFile(module.path) }.getOrNull() ?: return
        val elf = runCatching { ElfParser(image) }.getOrNull() ?: return
        val hits = BytePattern(rule.pattern).findAll(image)
        if (hits.size != 1) {
            return
        }

        val instructionRva = elf.fileOffsetToRva(hits.single().toLong()) ?: return
        val rva = when (val extraction = rule.extraction) {
            is Extraction.RipRelative -> {
                val displacement = readI32(image, hits.single() + extraction.displacementOffset)
                instructionRva + extraction.displacementOffset + extraction.bytesAfterDisplacement + displacement
            }

            is Extraction.I8 -> image[hits.single() + extraction.valueOffset].toLong() and 0xFF
            is Extraction.I32 -> readI32(image, hits.single() + extraction.valueOffset).toLong()
            is Extraction.CallTargetRipRelative -> {
                val callDisplacement = readI32(image, hits.single() + extraction.callDisplacementOffset)
                val targetRva = instructionRva + extraction.callDisplacementOffset + 4 + callDisplacement
                val targetFileOffset = elf.rvaToFileOffset(targetRva)?.toInt() ?: return
                val targetDisplacement = readI32(image, targetFileOffset + extraction.targetDisplacementOffset)
                targetRva + extraction.targetDisplacementOffset + extraction.targetBytesAfterDisplacement + targetDisplacement
            }
        }

        emit(
            OffsetEntry(
                name = rule.name,
                moduleName = module.name,
                rva = rva,
                access = rule.access,
                discovery = "osiris_linux_pattern",
                note = rule.note,
            ),
            log,
        )
    }

    private fun resolveMember(rule: MemberRule, log: (String) -> Unit) {
        val module = modules.firstOrNull { it.name == rule.moduleName } ?: return
        val image = runCatching { readFile(module.path) }.getOrNull() ?: return
        val hits = BytePattern(rule.pattern).findAll(image)
        if (hits.size != 1) {
            return
        }

        val offset = when (val extraction = rule.extraction) {
            is Extraction.I8 -> image[hits.single() + extraction.valueOffset].toLong() and 0xFF
            is Extraction.I32 -> readI32(image, hits.single() + extraction.valueOffset).toLong()
            is Extraction.RipRelative, is Extraction.CallTargetRipRelative -> return
        }

        emit(
            OffsetEntry(
                name = rule.name,
                moduleName = module.name,
                rva = offset,
                access = "member_offset",
                discovery = "osiris_linux_pattern",
                note = rule.note,
            ),
            log,
        )
    }

    private data class ButtonCandidate(
        val slot: Int,
        val rawName: String,
        val stateRva: Long,
        val observedState: Long,
    )

    private fun resolveButtons(log: (String) -> Unit) {
        val client = modules.firstOrNull { it.name == "libclient.so" } ?: return

        val csgoInputRva = entries
            .firstOrNull { it.moduleName == client.name && it.name == "dwCSGOInput" }
            ?.rva

        if (csgoInputRva == null) {
            return
        }

        val csgoInput = client.base + csgoInputRva

        val candidates = mutableMapOf<String, MutableList<ButtonCandidate>>()
        val encountered = mutableSetOf<String>()

        for (slot in 0 until CCSGO_INPUT_BUTTON_SLOT_COUNT) {
            val buttonObject = runCatching {
                mem.readPtr(
                    csgoInput + CCSGO_INPUT_BUTTON_POINTERS + slot * POINTER_SIZE,
                )
            }.getOrNull() ?: continue

            if (buttonObject == 0L) continue

            val namePointer = runCatching {
                mem.readPtr(buttonObject + KEY_BUTTON_NAME_POINTER)
            }.getOrNull() ?: continue

            if (namePointer == 0L) continue

            val rawName = runCatching {
                mem.readString(namePointer, 64)
            }.getOrNull() ?: continue

            val buttonName = normaliseButtonName(rawName) ?: continue
            if (buttonName !in SUPPORTED_BUTTON_NAMES) continue

            encountered += buttonName

            val stateAddress = buttonObject + KEY_BUTTON_STATE
            val stateRva = stateAddress - client.base

            if (stateRva < 0L) {
                continue
            }

            val state = runCatching {
                mem.readU32(stateAddress)
            }.getOrElse {
                continue
            }

            candidates
                .getOrPut(buttonName) { mutableListOf() }
                .add(
                    ButtonCandidate(
                        slot = slot,
                        rawName = rawName,
                        stateRva = stateRva,
                        observedState = state,
                    )
                )
        }

        for (buttonName in SUPPORTED_BUTTON_NAMES) {
            val matches = candidates[buttonName].orEmpty()
                .distinctBy { it.stateRva }

            when {
                matches.isEmpty() && buttonName !in encountered -> Unit

                matches.size > 1 -> Unit

                matches.size == 1 -> {
                    val match = matches.single()

                    emit(
                        OffsetEntry(
                            name = "buttons_$buttonName",
                            moduleName = client.name,
                            rva = match.stateRva,
                            access = "direct_address_rva",
                            discovery = "live_ccsgoinput_keybutton_state",
                            note = "a2x-compatible KeyButton.state RVA. " +
                                    "This is a 32-bit state field; write the complete state value.",
                        ),
                        log,
                    )
                }
            }
        }
    }

    private fun normaliseButtonName(rawName: String): String? {
        val normalised = rawName
            .trim()
            .trimStart('+')
            .lowercase()
            .replace(Regex("[^a-z0-9_]"), "")

        return normalised.takeIf { it.isNotEmpty() }
    }

    private fun emit(entry: OffsetEntry, log: (String) -> Unit) {
        if (entries.none { it.moduleName == entry.moduleName && it.name == entry.name }) {
            entries += entry
            log("  [offset] ${entry.moduleName}:${entry.name} = 0x${entry.rva.toULong().toString(16)}")
        }
    }

    private fun readI32(bytes: ByteArray, at: Int): Int =
        (bytes[at].toInt() and 0xFF) or
                ((bytes[at + 1].toInt() and 0xFF) shl 8) or
                ((bytes[at + 2].toInt() and 0xFF) shl 16) or
                (bytes[at + 3].toInt() shl 24)

    private sealed interface Extraction {
        data class RipRelative(val displacementOffset: Int, val bytesAfterDisplacement: Int = 4) : Extraction
        data class I8(val valueOffset: Int) : Extraction
        data class I32(val valueOffset: Int) : Extraction
        data class CallTargetRipRelative(
            val callDisplacementOffset: Int,
            val targetDisplacementOffset: Int,
            val targetBytesAfterDisplacement: Int = 4,
        ) : Extraction
    }

    private data class GlobalRule(
        val name: String,
        val moduleName: String,
        val pattern: String,
        val access: String,
        val extraction: Extraction,
        val note: String,
    )

    private data class MemberRule(
        val name: String,
        val moduleName: String,
        val pattern: String,
        val extraction: Extraction,
        val note: String,
    )

    private class BytePattern(pattern: String) {
        private val tokens: List<Int?> = pattern.trim().split(Regex("\\s+")).map { token ->
            if (token == "?" || token == "??") null else token.toInt(16)
        }
        private val anchor = tokens.indexOfFirst { it != null }.coerceAtLeast(0)

        fun findAll(bytes: ByteArray): List<Int> {
            if (tokens.isEmpty() || bytes.size < tokens.size) return emptyList()
            val results = mutableListOf<Int>()
            val last = bytes.size - tokens.size
            for (at in 0..last) {
                val expectedAnchor = tokens[anchor]
                if (expectedAnchor != null && (bytes[at + anchor].toInt() and 0xFF) != expectedAnchor) continue
                var matches = true
                for (i in tokens.indices) {
                    val expected = tokens[i] ?: continue
                    if ((bytes[at + i].toInt() and 0xFF) != expected) {
                        matches = false
                        break
                    }
                }
                if (matches) results += at
            }
            return results
        }
    }

    companion object {
        private val globalRules = listOf(
            GlobalRule(
                "dwGlobalVars", "libclient.so",
                "8D ?? ?? ?? ?? ?? 48 89 35 ?? ?? ?? ?? 48 89 ?? ?? C3",
                "pointer_slot_rva", Extraction.RipRelative(9), "Osiris GlobalVarsPointer.",
            ),
            GlobalRule(
                "dwWorldToProjectionMatrix", "libclient.so",
                "01 4C 8D 05 ?? ?? ?? ?? 4C 89 EE",
                "direct_address_rva", Extraction.RipRelative(4), "Osiris WorldToProjectionMatrixPointer.",
            ),
            GlobalRule(
                "dwViewMatrix", "libclient.so",
                "01 4C 8D 05 ?? ?? ?? ?? 4C 89 EE",
                "direct_address_rva", Extraction.RipRelative(4), "Alias for native world-to-projection matrix storage.",
            ),
            GlobalRule(
                "dwViewToProjectionMatrix", "libclient.so",
                "EE 48 8D 0D ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48",
                "direct_address_rva", Extraction.RipRelative(4), "Osiris ViewToProjectionMatrixPointer.",
            ),
            GlobalRule(
                "dwViewRender", "libclient.so",
                "48 8D 05 ?? ?? ?? ?? 48 89 38 48 85",
                "pointer_slot_rva", Extraction.RipRelative(3), "Osiris ViewRenderPointer.",
            ),
            GlobalRule(
                "dwLocalPlayerController", "libclient.so",
                "48 83 3D ?? ?? ?? ?? ?? 0F 95 C0 C3",
                "pointer_slot_rva", Extraction.RipRelative(3, 5), "Osiris LocalPlayerControllerPointer.",
            ),
            GlobalRule(
                "dwGameEntitySystem", "libclient.so",
                "4C 63 ?? ?? ?? ?? ?? 48 89 1D ?? ?? ?? ??",
                "pointer_slot_rva", Extraction.RipRelative(10), "Osiris EntitySystemPointer.",
            ),
            GlobalRule(
                "dwGameRules", "libclient.so",
                "FF 53 ?? 48 83 3D ?? ?? ?? ?? 00 74",
                "pointer_slot_rva", Extraction.RipRelative(6, 5), "Osiris GameRulesPointer.",
            ),
            GlobalRule(
                "dwPlantedC4s", "libclient.so",
                "80 BF ?? ?? ?? ?? 00 0F 84 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 8B 10",
                "direct_address_rva", Extraction.RipRelative(16), "Osiris PlantedC4sPointer (vector storage).",
            ),
            GlobalRule(
                name = "dwCSGOInput",
                moduleName = "libclient.so",
                pattern =
                    "4C 8D 3D ?? ?? ?? ?? " +        // LEA R15,[g_CCSGOInput]
                            "E8 ?? ?? ?? ?? " +       // CALL FUN_01ad5da0
                            "48 89 C7 " +             // MOV RDI,RAX
                            "48 85 C0 " +             // TEST RAX,RAX
                            "0F 84 ?? ?? ?? ?? " +    // JZ ...
                            "48 8B 00 " +             // MOV RAX,[RAX]
                            "FF 50 08 " +             // CALL [RAX + 0x8]
                            "BA 01 00 00 00 " +       // MOV EDX,1
                            "84 C0 " +                // TEST AL,AL
                            "0F 84 ?? ?? ?? ??",      // JZ ...
                access = "direct_address_rva",
                extraction = Extraction.RipRelative(3),
                note = "Linux CCSGOInput direct global object, verified through CreateMove vtable method.",
            ),
            GlobalRule(
                name = "sdlKeyboardFocus",
                moduleName = "libSDL3.so.0",
                pattern =
                    "48 83 3D ?? ?? ?? ?? 00 " + // CMP qword ptr [video_device],0
                            "74 ?? " +
                            "53 " +
                            "89 FB " +
                            "40 84 FF " +
                            "74 ?? " +
                            "E8 ?? ?? ?? ?? " +    // CALL SDL_GetKeyboardFocus implementation
                            "48 85 C0 " +
                            "74 ?? " +
                            "88 1D ?? ?? ?? ?? " +
                            "31 FF " +
                            "5B " +
                            "E9",
                access = "pointer_slot_rva",
                extraction = Extraction.CallTargetRipRelative(
                    callDisplacementOffset = 19,
                    targetDisplacementOffset = 3,
                ),
                note = "Bundled SDL3 keyboard-focus window pointer. Null when the CS2 Wayland window has no keyboard focus.",
            ),
        )

        private val memberRules = listOf(
            MemberRule(
                "CGameEntitySystem_m_EntityList", "libclient.so",
                "4C 8D 6F ?? 41 54 53 48 89 FB 48 83 EC ?? 48 89 07 48",
                Extraction.I8(3), "Osiris EntityListOffset.",
            ),
            MemberRule(
                "CGameEntitySystem_m_EntityClasses", "libclient.so",
                "49 8B 8F ?? ?? ?? ?? 0F B7",
                Extraction.I32(3), "Osiris OffsetToEntityClasses.",
            ),
        )

        private const val CCSGO_INPUT_BUTTON_POINTERS = 0x10L
        private const val CCSGO_INPUT_BUTTON_SLOT_COUNT = 64
        private const val POINTER_SIZE = 0x8L

        private const val KEY_BUTTON_NAME_POINTER = 0x08L
        private const val KEY_BUTTON_STATE = 0x30L

        private val SUPPORTED_BUTTON_NAMES = linkedSetOf(
            "attack",
            "attack2",
            "back",
            "duck",
            "forward",
            "jump",
            "left",
            "lookatweapon",
            "reload",
            "right",
            "showscores",
            "sprint",
            "turnleft",
            "turnright",
            "use",
            "zoom",
        )
    }
}
