package org.kvxd.source2offset.engine

import org.kvxd.source2offset.core.MemReader
import org.kvxd.source2offset.engine.rtti.RttiInspector
import org.kvxd.source2offset.export.InterfaceEntry
import org.kvxd.source2offset.export.RuntimeRootEntry

class RuntimeRootDumper(
    private val mem: MemReader,
    private val rtti: RttiInspector,
    private val exportTargetTypes: Set<String> = setOf("CGameEntitySystem"),
) {
    fun dump(interfaces: Collection<InterfaceEntry>, log: (String) -> Unit = {}): List<RuntimeRootEntry> {
        val roots = mutableListOf<RuntimeRootEntry>()
        val emitted = mutableSetOf<Triple<String, Long, String>>()

        for (source in interfaces) {
            rtti.inspectObject(source.address)?.let { info ->
                log("  [rtti] ${source.name} instance type: ${info.typeName}")
            }

            for (offset in 0L until MAX_MEMBER_SCAN_BYTES step POINTER_SIZE) {
                val target = runCatching { mem.readPtr(source.address + offset) }.getOrDefault(0L)
                if (target == 0L) continue

                val type = rtti.inspectObject(target) ?: continue
                if (type.typeName !in exportTargetTypes) continue

                val key = Triple(source.name, offset, type.typeName)
                if (!emitted.add(key)) continue

                roots += RuntimeRootEntry(
                    name = type.typeName.removePrefix("C"),
                    sourceModule = source.moduleName,
                    sourceInterface = source.name,
                    sourceInterfaceRva = source.rva,
                    memberOffset = offset,
                    targetType = type.typeName,
                    targetAddress = target,
                )
                log("  [root] ${source.name}+0x${offset.toString(16)} -> ${type.typeName}")
            }
        }

        return roots.sortedWith(compareBy({ it.name }, { it.sourceInterface }, { it.memberOffset }))
    }

    companion object {
        private const val POINTER_SIZE = 8L
        private const val MAX_MEMBER_SCAN_BYTES = 0x400L
    }
}
