package org.kvxd.source2offset.engine

import org.kvxd.source2offset.core.MemReader
import org.kvxd.source2offset.core.MemoryMapping
import org.kvxd.source2offset.core.Module
import org.kvxd.source2offset.engine.rtti.RttiInspector
import org.kvxd.source2offset.export.DumpResult
import org.kvxd.source2offset.export.InterfaceEntry
import org.kvxd.source2offset.export.normaliseModuleName
import org.kvxd.source2offset.schema.SchemaDumper

class DumpEngine(
    private val mem: MemReader,
    private val gameModules: List<Module>,
    private val modulesForSymbols: List<Module>,
    private val includeSymbols: Boolean,
    private val includePrivateOffsets: Boolean,
    private val mappings: List<MemoryMapping>,
    private val resolvedInterfaces: List<InterfaceEntry>,
    private val readFile: (String) -> ByteArray,
    private val timestamp: String,
    private val log: (String) -> Unit = {},
    private val progress: (String) -> Unit = {},
) {
    fun run(): DumpResult {
        val interfaceMap = resolvedInterfaces
            .groupBy { normaliseModuleName(it.moduleName) }
            .mapValues { (_, entries) -> entries.sortedBy { it.name } }

        val symbols = if (includeSymbols) {
            progress("Writing ELF symbols...")
            SymbolDumper(readFile).dump(modulesForSymbols, log)
        } else {
            emptyMap()
        }

        progress("Dumping schema metadata...")
        val schemaInterface = resolvedInterfaces.firstOrNull { it.name == "SchemaSystem_001" }
        val schemas = if (schemaInterface == null) {
            emptyList()
        } else {
            runCatching { SchemaDumper(mem).dump(schemaInterface.address, log) }
                .getOrElse { error ->
                    log("ERROR: schema dump failed: ${error.message}")
                    emptyList()
                }
        }

        val rtti = RttiInspector(mem, mappings)
        progress("Inspecting runtime roots...")
        val roots = RuntimeRootDumper(mem, rtti).dump(resolvedInterfaces, log)

        val offsetResult = if (includePrivateOffsets) {
            progress("Dumping offsets...")
            NativeOffsetDumper(mem, gameModules, rtti, readFile).dump(resolvedInterfaces, roots, log)
        } else {
            OffsetDiscoveryResult(
                offsets = emptyMap(),
            )
        }

        return DumpResult(
            timestamp = timestamp,
            interfaces = interfaceMap,
            offsets = offsetResult.offsets,
            schemas = schemas,
            symbols = symbols,
            runtimeRoots = roots,
        )
    }
}
