package org.kvxd.source2offset.engine

import org.kvxd.source2offset.core.MemReader
import org.kvxd.source2offset.core.Module
import org.kvxd.source2offset.export.OffsetEntry

internal class ButtonOffsetResolver(
    private val mem: MemReader,
    private val modules: List<Module>,
    private val collector: OffsetCollector,
) {
    fun resolve() {
        val client = modules.firstOrNull { it.name == "libclient.so" } ?: return
        val csgoInputRva = collector.entries
            .firstOrNull { it.moduleName == client.name && it.name == "dwCSGOInput" }
            ?.rva
            ?: return

        val csgoInput = client.base + csgoInputRva
        val candidates = mutableMapOf<String, MutableList<ButtonCandidate>>()
        val encountered = mutableSetOf<String>()

        for (slot in 0 until CCSGO_INPUT_BUTTON_SLOT_COUNT) {
            val buttonObject = runCatching {
                mem.readPtr(csgoInput + CCSGO_INPUT_BUTTON_POINTERS + slot * POINTER_SIZE)
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
                matches.size == 1 -> emitButton(client, buttonName, matches.single())
            }
        }
    }

    private fun emitButton(client: Module, buttonName: String, match: ButtonCandidate) {
        collector.emit(
            OffsetEntry(
                name = "buttons_$buttonName",
                moduleName = client.name,
                rva = match.stateRva,
                access = "direct_address_rva",
                discovery = "live_ccsgoinput_keybutton_state",
            )
        )
    }

    private fun normaliseButtonName(rawName: String): String? {
        val normalised = rawName
            .trim()
            .trimStart('+')
            .lowercase()
            .replace(Regex("[^a-z0-9_]"), "")

        return normalised.takeIf { it.isNotEmpty() }
    }

    private data class ButtonCandidate(
        @Suppress("unused") val slot: Int,
        @Suppress("unused") val rawName: String,
        val stateRva: Long,
        @Suppress("unused") val observedState: Long,
    )

    private companion object {
        private const val CCSGO_INPUT_BUTTON_POINTERS = 0x10L
        private const val CCSGO_INPUT_BUTTON_SLOT_COUNT = 64
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
