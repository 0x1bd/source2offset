package org.kvxd.source2offset.engine

import org.kvxd.source2offset.core.MemReader
import org.kvxd.source2offset.core.Module
import org.kvxd.source2offset.elf.ElfParser
import org.kvxd.source2offset.engine.rtti.RttiInspector
import org.kvxd.source2offset.export.CapabilityMessage
import org.kvxd.source2offset.export.InterfaceEntry
import org.kvxd.source2offset.export.OffsetEntry
import org.kvxd.source2offset.export.RuntimeRootEntry
import org.kvxd.source2offset.export.normaliseModuleName

data class OffsetDiscoveryResult(
    val offsets: Map<String, List<OffsetEntry>>,
    val messages: List<CapabilityMessage>,
)

@Suppress("UNUSED_PARAMETER")
class NativeOffsetDumper(
    private val mem: MemReader,
    private val modules: List<Module>,
    private val rtti: RttiInspector,
    private val readFile: (String) -> ByteArray,
) {
    private val entries = mutableListOf<OffsetEntry>()
    private val messages = mutableListOf<CapabilityMessage>()

    fun dump(
        interfaces: List<InterfaceEntry>,
        runtimeRoots: List<RuntimeRootEntry>,
        log: (String) -> Unit = {},
    ): OffsetDiscoveryResult {
        log("Discovering native Linux global offsets with Osiris-style patterns...")

        globalRules.forEach { resolveGlobal(it, log) }
        memberRules.forEach { resolveMember(it, log) }

        val grouped = entries
            .groupBy { normaliseModuleName(it.moduleName) }
            .mapValues { (_, values) -> values.sortedBy { it.name } }

        messages += CapabilityMessage(
            if (grouped.isEmpty()) "warning" else "ok",
            "global_offsets",
            if (grouped.isEmpty()) {
                "No reviewed native Linux pattern matched uniquely in this run."
            } else {
                "Emitted ${grouped.values.sumOf { it.size }} native Linux target(s) from unique Osiris-style pattern matches."
            },
        )
        messages += CapabilityMessage(
            "provenance",
            "osiris_linux_patterns",
            "Patterns are adapted from Osiris Linux MemoryPatterns (MIT); schema-reflected fields are still emitted from live SchemaSystem rather than duplicated here.",
        )
        messages += CapabilityMessage(
            "unavailable",
            "dwLocalPlayerPawn",
            "Osiris Linux does not define a local-pawn global pattern, and the historical a2x Linux dwLocalPlayerPawn rule does not match this supplied libclient.so. Derive the local pawn from dwLocalPlayerController + reflected m_hPlayerPawn through CGameEntitySystem.",
        )

        return OffsetDiscoveryResult(grouped, messages)
    }

    private fun resolveGlobal(rule: GlobalRule, log: (String) -> Unit) {
        val module = modules.firstOrNull { it.name == rule.moduleName } ?: return
        val image = runCatching { readFile(module.path) }.getOrNull() ?: return
        val elf = runCatching { ElfParser(image) }.getOrNull() ?: return
        val hits = BytePattern(rule.pattern).findAll(image)
        if (hits.size != 1) {
            messages += CapabilityMessage(
                "unavailable",
                rule.name,
                "Pattern in ${module.name} matched ${hits.size} location(s); expected one.",
            )
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
        }

        emit(
            OffsetEntry(
                name = rule.name,
                moduleName = module.name,
                rva = rva,
                access = rule.access,
                discovery = "osiris_linux_pattern",
                validation = "unique_pattern_match",
                confidence = "signature",
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
            messages += CapabilityMessage(
                "unavailable",
                rule.name,
                "Pattern in ${module.name} matched ${hits.size} location(s); expected one.",
            )
            return
        }

        val offset = when (val extraction = rule.extraction) {
            is Extraction.I8 -> image[hits.single() + extraction.valueOffset].toLong() and 0xFF
            is Extraction.I32 -> readI32(image, hits.single() + extraction.valueOffset).toLong()
            is Extraction.RipRelative -> return
        }

        emit(
            OffsetEntry(
                name = rule.name,
                moduleName = module.name,
                rva = offset,
                access = "member_offset",
                discovery = "osiris_linux_pattern",
                validation = "unique_pattern_match",
                confidence = "signature",
                note = rule.note,
            ),
            log,
        )
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
    }
}