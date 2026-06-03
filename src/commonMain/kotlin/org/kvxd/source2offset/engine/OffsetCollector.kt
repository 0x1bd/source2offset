package org.kvxd.source2offset.engine

import org.kvxd.source2offset.export.OffsetEntry

internal class OffsetCollector(
    private val log: (String) -> Unit,
) {
    private val collected = mutableListOf<OffsetEntry>()

    val entries: List<OffsetEntry>
        get() = collected

    fun emit(entry: OffsetEntry) {
        if (collected.none { it.moduleName == entry.moduleName && it.name == entry.name }) {
            collected += entry
            log("  [offset] ${entry.moduleName}:${entry.name} = 0x${entry.rva.toULong().toString(16)}")
        }
    }
}
