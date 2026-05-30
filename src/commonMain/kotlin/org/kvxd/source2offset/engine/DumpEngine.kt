package org.kvxd.source2offset.engine

import org.kvxd.source2offset.core.MemReader
import org.kvxd.source2offset.core.MemoryMapping
import org.kvxd.source2offset.core.Module
import org.kvxd.source2offset.engine.rtti.RttiInspector
import org.kvxd.source2offset.export.CapabilityMessage
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
) {
    fun run(): DumpResult {
        val capabilities = mutableListOf<CapabilityMessage>()
        val interfaceMap = resolvedInterfaces
            .groupBy { normaliseModuleName(it.moduleName) }
            .mapValues { (_, entries) -> entries.sortedBy { it.name } }

        if (resolvedInterfaces.isEmpty()) {
            capabilities += CapabilityMessage("error", "interfaces", "No named CreateInterface calls resolved successfully.")
        } else {
            capabilities += CapabilityMessage("ok", "interfaces", "Resolved ${resolvedInterfaces.size} named interface instance(s) through live CreateInterface calls.")
        }

        val symbols = if (includeSymbols) {
            log("Extracting retained ELF symbols (diagnostic output requested)...")
            SymbolDumper(readFile).dump(modulesForSymbols, log).also { found ->
                capabilities += CapabilityMessage(
                    if (found.isEmpty()) "warning" else "ok",
                    "elf_symbols",
                    if (found.isEmpty()) "No named ELF symbols were retained in requested mapped game modules."
                    else "Exported diagnostic retained symbol metadata from ${found.size} module(s).",
                )
            }
        } else {
            capabilities += CapabilityMessage(
                "not_requested",
                "elf_symbols",
                "Retained ELF symbol export is disabled by default; pass --symbols when investigating exported names.",
            )
            emptyMap()
        }

        log("Dumping schema metadata...")
        val schemaInterface = resolvedInterfaces.firstOrNull { it.name == "SchemaSystem_001" }
        val schemas = if (schemaInterface == null) {
            capabilities += CapabilityMessage("error", "schema", "SchemaSystem_001 was not resolved; reflected fields cannot be dumped.")
            emptyList()
        } else {
            runCatching { SchemaDumper(mem).dump(schemaInterface.address, log) }
                .onSuccess {
                    capabilities += CapabilityMessage("ok", "schema", "Dumped every field and enum visible through live SchemaSystem metadata.")
                }
                .getOrElse { error ->
                    capabilities += CapabilityMessage("error", "schema", error.message ?: "Schema dump failed.")
                    log("ERROR: schema dump failed: ${error.message}")
                    emptyList()
                }
        }

        val rtti = RttiInspector(mem, mappings)
        log("Inspecting RTTI-visible relationships from named interfaces...")
        val roots = RuntimeRootDumper(mem, rtti).dump(resolvedInterfaces, log)
        val entityRoot = roots.firstOrNull { it.targetType.contains("EntitySystem", ignoreCase = true) }
        if (entityRoot != null) {
            capabilities += CapabilityMessage(
                "ok",
                "entity_system_root",
                "Verified ${entityRoot.targetType} through ${entityRoot.sourceInterface}+0x${entityRoot.memberOffset.toString(16)} using live RTTI.",
            )
        } else {
            capabilities += CapabilityMessage(
                "unavailable",
                "entity_system_root",
                "No RTTI-verifiable entity-system relationship was reachable from the requested interfaces.",
            )
        }

        val offsetResult = if (includePrivateOffsets) {
            NativeOffsetDumper(mem, gameModules, rtti, readFile).dump(resolvedInterfaces, roots, log)
        } else {
            OffsetDiscoveryResult(
                offsets = emptyMap(),
                messages = listOf(
                    CapabilityMessage(
                        "not_requested",
                        "global_offsets",
                        "Private/global dw* extraction is disabled; pass --offsets to enable validated native-Linux analysis.",
                    )
                ),
            )
        }
        capabilities += offsetResult.messages

        capabilities += CapabilityMessage(
            if (includePrivateOffsets) "hybrid" else "metadata_only",
            "private_global_offsets",
            if (includePrivateOffsets) {
                "Private globals are emitted only after live validation; signature-backed discoveries are marked in offsets metadata."
            } else {
                "No private/global analysis was requested; only interface, schema and RTTI metadata was emitted."
            },
        )

        return DumpResult(
            timestamp = timestamp,
            interfaces = interfaceMap,
            offsets = offsetResult.offsets,
            schemas = schemas,
            symbols = symbols,
            runtimeRoots = roots,
            capabilities = capabilities,
        )
    }
}
