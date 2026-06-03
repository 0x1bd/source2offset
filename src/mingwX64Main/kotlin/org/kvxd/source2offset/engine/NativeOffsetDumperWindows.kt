package org.kvxd.source2offset.engine

import org.kvxd.source2offset.core.MemReader
import org.kvxd.source2offset.core.Module
import org.kvxd.source2offset.export.OffsetEntry
import org.kvxd.source2offset.export.normaliseModuleName

actual class NativeOffsetDumper actual constructor(
    private val mem: MemReader,
    private val modules: List<Module>,
    @Suppress("unused") private val readFile: (String) -> ByteArray,
) {
    actual fun dump(log: (String) -> Unit): OffsetDiscoveryResult {
        log("Dumping Windows offsets from live PE module patterns...")

        val collector = OffsetCollector(log)
        WINDOWS_PATTERN_RULES.forEach { resolveRule(it, collector) }
        resolveButtons(collector)

        val grouped = collector.entries
            .groupBy { normaliseModuleName(it.moduleName) }
            .mapValues { (_, values) -> values.sortedBy { it.name } }

        return OffsetDiscoveryResult(grouped)
    }

    private fun resolveRule(rule: WindowsPatternRule, collector: OffsetCollector) {
        val module = modules.firstOrNull { it.name.equals(rule.moduleName, ignoreCase = true) } ?: return
        val image = readModuleImage(module) ?: return
        val hit = BytePattern(rule.pattern).findAll(image).singleOrNull() ?: return
        val value = when (val extraction = rule.extraction) {
            is WindowsExtraction.RipRelative -> ripRelativeRva(image, hit, extraction.displacementOffset, extraction.bytesAfterDisplacement)
            is WindowsExtraction.I8 -> image[hit + extraction.valueOffset].toLong() and 0xFF
            is WindowsExtraction.I32 -> readI32(image, hit + extraction.valueOffset).toLong()
        }

        collector.emit(
            OffsetEntry(
                name = rule.name,
                moduleName = module.name,
                rva = value,
                access = rule.access,
                discovery = "windows_pe_pattern",
            )
        )

        rule.afterResolve?.invoke(image, hit, value, collector, module)
    }

    private fun resolveButtons(collector: OffsetCollector) {
        val module = modules.firstOrNull { it.name.equals("client.dll", ignoreCase = true) } ?: return
        val image = readModuleImage(module) ?: return
        val hit = BytePattern("48 8B 15 ?? ?? ?? ?? 48 85 D2 74 ? 48 8B 02 48 85 C0").findAll(image).singleOrNull()
            ?: return
        val listSlotRva = ripRelativeRva(image, hit, 3, 4)
        val listHead = runCatching { mem.readPtr(module.base + listSlotRva) }.getOrNull() ?: return

        var buttonPtr = listHead
        val seen = mutableSetOf<Long>()
        repeat(MAX_BUTTONS) {
            if (buttonPtr == 0L || !seen.add(buttonPtr)) return@repeat

            val namePtr = runCatching { mem.readPtr(buttonPtr + KEY_BUTTON_NAME_POINTER) }.getOrNull() ?: return@repeat
            val rawName = runCatching { mem.readString(namePtr, 32) }.getOrNull().orEmpty()
            val buttonName = normaliseButtonName(rawName)
            val stateRva = buttonPtr + KEY_BUTTON_STATE - module.base
            if (buttonName != null && stateRva >= 0) {
                collector.emit(
                    OffsetEntry(
                        name = "buttons_$buttonName",
                        moduleName = module.name,
                        rva = stateRva,
                        access = "direct_address_rva",
                        discovery = "windows_keybutton_list",
                    )
                )
            }

            buttonPtr = runCatching { mem.readPtr(buttonPtr + KEY_BUTTON_NEXT_POINTER) }.getOrNull() ?: 0L
        }
    }

    private fun readModuleImage(module: Module): ByteArray? {
        val size = module.size.toLong()
        if (size <= 0L || size > Int.MAX_VALUE) return null
        return runCatching { mem.readBytes(module.base, size.toInt()) }.getOrNull()
    }

    private fun ripRelativeRva(image: ByteArray, hit: Int, displacementOffset: Int, bytesAfterDisplacement: Int): Long {
        val displacement = readI32(image, hit + displacementOffset)
        return hit.toLong() + displacementOffset + bytesAfterDisplacement + displacement
    }

    private fun normaliseButtonName(rawName: String): String? {
        val normalised = rawName
            .trim()
            .trimStart('+')
            .lowercase()
            .replace(Regex("[^a-z0-9_]"), "")

        return normalised.takeIf { it.isNotEmpty() }
    }

    private companion object {
        private const val KEY_BUTTON_NAME_POINTER = 0x08L
        private const val KEY_BUTTON_STATE = 0x30L
        private const val KEY_BUTTON_NEXT_POINTER = 0x88L
        private const val MAX_BUTTONS = 128
    }
}

private sealed interface WindowsExtraction {
    data class RipRelative(val displacementOffset: Int, val bytesAfterDisplacement: Int = 4) : WindowsExtraction
    data class I8(val valueOffset: Int) : WindowsExtraction
    data class I32(val valueOffset: Int) : WindowsExtraction
}

private data class WindowsPatternRule(
    val name: String,
    val moduleName: String,
    val pattern: String,
    val extraction: WindowsExtraction,
    val access: String = "direct_address_rva",
    val afterResolve: ((ByteArray, Int, Long, OffsetCollector, Module) -> Unit)? = null,
)

private val WINDOWS_PATTERN_RULES = listOf(
    WindowsPatternRule(
        "dwCSGOInput", "client.dll",
        "48 89 05 ?? ?? ?? ?? 0F 57 C0 0F 11 05",
        WindowsExtraction.RipRelative(3),
        afterResolve = { image, _, rva, collector, module ->
            val hit = BytePattern("F2 42 0F 10 84 28 ?? ?? ?? ??").findAll(image).singleOrNull() ?: return@WindowsPatternRule
            val offset = readI32(image, hit + 6)
            collector.emit(
                OffsetEntry(
                    name = "dwViewAngles",
                    moduleName = module.name,
                    rva = rva + offset,
                    access = "direct_address_rva",
                    discovery = "windows_pe_pattern",
                )
            )
        },
    ),
    WindowsPatternRule("dwEntityList", "client.dll", "48 89 0D ?? ?? ?? ?? E9 ?? ?? ?? ?? CC", WindowsExtraction.RipRelative(3)),
    WindowsPatternRule("dwGameEntitySystem", "client.dll", "48 8B 1D ?? ?? ?? ?? 48 89 1D ?? ?? ?? ?? 4C 63 B3", WindowsExtraction.RipRelative(3)),
    WindowsPatternRule("dwGameEntitySystem_highestEntityIndex", "client.dll", "FF 81 ?? ?? ?? ?? 48 85 D2", WindowsExtraction.I32(2), "member_offset"),
    WindowsPatternRule("dwGameRules", "client.dll", "F6 C1 01 0F 85 ?? ?? ?? ?? 4C 8B 05 ?? ?? ?? ?? 4D 85", WindowsExtraction.RipRelative(12)),
    WindowsPatternRule("dwGlobalVars", "client.dll", "48 89 15 ?? ?? ?? ?? 48 89 42", WindowsExtraction.RipRelative(3)),
    WindowsPatternRule("dwGlowManager", "client.dll", "48 8B 05 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC 8B 41", WindowsExtraction.RipRelative(3)),
    WindowsPatternRule("dwLocalPlayerController", "client.dll", "48 8B 05 ?? ?? ?? ?? 41 89 BE", WindowsExtraction.RipRelative(3)),
    WindowsPatternRule("dwPlantedC4", "client.dll", "48 8B 15 ?? ?? ?? ?? 41 FF C0 48 8D 4C 24 ? 44 89 05 ?? ?? ?? ??", WindowsExtraction.RipRelative(3)),
    WindowsPatternRule(
        "dwPrediction", "client.dll",
        "48 8D 05 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC 40 53 56 41 54",
        WindowsExtraction.RipRelative(3),
        afterResolve = { image, _, rva, collector, module ->
            val hit = BytePattern("4C 39 B6 ?? ?? ?? ?? 74 ? 44 88 BE").findAll(image).singleOrNull() ?: return@WindowsPatternRule
            val offset = readI32(image, hit + 3)
            collector.emit(
                OffsetEntry(
                    name = "dwLocalPlayerPawn",
                    moduleName = module.name,
                    rva = rva + offset,
                    access = "direct_address_rva",
                    discovery = "windows_pe_pattern",
                )
            )
        },
    ),
    WindowsPatternRule("dwSensitivity", "client.dll", "48 8D 0D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 0F 6E CD", WindowsExtraction.RipRelative(3, 12)),
    WindowsPatternRule("dwSensitivity_sensitivity", "client.dll", "48 8D 7E ?? 48 0F BA E0 ? 72 ? 85 D2 49 0F 4F FF", WindowsExtraction.I8(3), "member_offset"),
    WindowsPatternRule("dwViewMatrix", "client.dll", "48 8D 0D ?? ?? ?? ?? 48 C1 E0 06", WindowsExtraction.RipRelative(3)),
    WindowsPatternRule("dwViewRender", "client.dll", "48 89 05 ?? ?? ?? ?? 48 8B C8 48 85 C0", WindowsExtraction.RipRelative(3)),
    WindowsPatternRule("dwWeaponC4", "client.dll", "48 8B 15 ?? ?? ?? ?? 48 8B 5C 24 ? FF C0 89 05 ?? ?? ?? ?? 48 8B C6 48 89 34 EA 80 BE", WindowsExtraction.RipRelative(3)),
    WindowsPatternRule("dwBuildNumber", "engine2.dll", "89 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B 0D", WindowsExtraction.RipRelative(2)),
    WindowsPatternRule("dwNetworkGameClient", "engine2.dll", "48 89 3D ?? ?? ?? ?? FF 87", WindowsExtraction.RipRelative(3)),
    WindowsPatternRule("dwNetworkGameClient_clientTickCount", "engine2.dll", "8B 81 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC CC CC CC 8B 81 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC CC CC CC 83 B9", WindowsExtraction.I32(2), "member_offset"),
    WindowsPatternRule("dwNetworkGameClient_deltaTick", "engine2.dll", "4C 8D B7 ?? ?? ?? ?? 4C 89 7C 24", WindowsExtraction.I32(3), "member_offset"),
    WindowsPatternRule("dwNetworkGameClient_isBackgroundMap", "engine2.dll", "0F B6 81 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC 0F B6 81 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC 40 53", WindowsExtraction.I32(3), "member_offset"),
    WindowsPatternRule("dwNetworkGameClient_localPlayer", "engine2.dll", "42 8B 94 D3 ?? ?? ?? ?? 5B 49 FF E3 32 C0 5B C3 CC CC CC CC CC CC CC CC CC CC 40 53", WindowsExtraction.I32(4), "member_offset"),
    WindowsPatternRule("dwNetworkGameClient_maxClients", "engine2.dll", "8B 81 ?? ?? ?? ?? C3 ? ? ? ? ? ? ? ? ? 8B 81 ?? ?? ?? ?? C3 ? ? ? ? ? ? ? ? ? 8B 81", WindowsExtraction.I32(2), "member_offset"),
    WindowsPatternRule("dwNetworkGameClient_serverTickCount", "engine2.dll", "8B 81 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC CC CC CC 83 B9", WindowsExtraction.I32(2), "member_offset"),
    WindowsPatternRule("dwNetworkGameClient_signOnState", "engine2.dll", "44 8B 81 ?? ?? ?? ?? 48 8D 0D", WindowsExtraction.I32(3), "member_offset"),
    WindowsPatternRule("dwWindowHeight", "engine2.dll", "8B 05 ?? ?? ?? ?? 89 03", WindowsExtraction.RipRelative(2)),
    WindowsPatternRule("dwWindowWidth", "engine2.dll", "8B 05 ?? ?? ?? ?? 89 07", WindowsExtraction.RipRelative(2)),
    WindowsPatternRule("dwInputSystem", "inputsystem.dll", "48 89 05 ?? ?? ?? ?? 33 C0", WindowsExtraction.RipRelative(3)),
    WindowsPatternRule("dwGameTypes", "matchmaking.dll", "48 8D 0D ?? ?? ?? ?? FF 90", WindowsExtraction.RipRelative(3)),
    WindowsPatternRule("dwSoundSystem", "soundsystem.dll", "48 8D 05 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC 48 89 15", WindowsExtraction.RipRelative(3)),
    WindowsPatternRule("dwSoundSystem_engineViewData", "soundsystem.dll", "0F 11 47 ?? 0F 10 4E ? 0F 11 8F", WindowsExtraction.I8(3), "member_offset"),
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
        val expectedAnchor = tokens[anchor]
        var searchStart = 0

        while (searchStart <= last) {
            val at = if (expectedAnchor == null) {
                searchStart
            } else {
                val anchorHit = indexOfByte(bytes, expectedAnchor, searchStart + anchor)
                if (anchorHit < 0 || anchorHit - anchor > last) break
                anchorHit - anchor
            }

            var matches = true
            for (i in tokens.indices) {
                val expected = tokens[i] ?: continue
                if ((bytes[at + i].toInt() and 0xFF) != expected) {
                    matches = false
                    break
                }
            }
            if (matches) results += at
            searchStart = at + 1
        }
        return results
    }

    private fun indexOfByte(bytes: ByteArray, value: Int, startIndex: Int): Int {
        var at = startIndex.coerceAtLeast(0)
        val byteValue = value.toByte()
        while (at < bytes.size) {
            if (bytes[at] == byteValue) return at
            at++
        }
        return -1
    }
}

private fun readI32(bytes: ByteArray, at: Int): Int =
    (bytes[at].toInt() and 0xFF) or
            ((bytes[at + 1].toInt() and 0xFF) shl 8) or
            ((bytes[at + 2].toInt() and 0xFF) shl 16) or
            (bytes[at + 3].toInt() shl 24)
