package org.kvxd.source2offset.engine

import org.kvxd.source2offset.core.MemReader
import org.kvxd.source2offset.core.Module
import org.kvxd.source2offset.export.OffsetEntry
import org.kvxd.source2offset.export.normaliseModuleName

actual class NativeOffsetDumper actual constructor(
    private val mem: MemReader,
    private val modules: List<Module>,
    private val readFile: (String) -> ByteArray,
) {
    actual fun dump(log: (String) -> Unit): OffsetDiscoveryResult {
        log("Dumping raw offsets...")

        val collector = OffsetCollector(log)
        val patternResolver = PatternOffsetResolver(modules, readFile, collector)

        patternResolver.resolveGlobals(LINUX_GLOBAL_OFFSET_RULES)
        ButtonOffsetResolver(mem, modules, collector).resolve()
        NetworkVarFieldOffsetResolver(modules, readFile, collector).resolve()
        patternResolver.resolveMembers(LINUX_MEMBER_OFFSET_RULES)

        val grouped = collector.entries
            .groupBy { normaliseModuleName(it.moduleName) }
            .mapValues { (_, values) -> values.sortedBy { it.name } }

        return OffsetDiscoveryResult(grouped)
    }
}
