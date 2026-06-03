package org.kvxd.source2offset.engine

import org.kvxd.source2offset.core.MemReader
import org.kvxd.source2offset.core.Module
import org.kvxd.source2offset.export.OffsetEntry

data class OffsetDiscoveryResult(
    val offsets: Map<String, List<OffsetEntry>>,
)

expect class NativeOffsetDumper(
    mem: MemReader,
    modules: List<Module>,
    readFile: (String) -> ByteArray,
) {
    fun dump(log: (String) -> Unit = {}): OffsetDiscoveryResult
}
