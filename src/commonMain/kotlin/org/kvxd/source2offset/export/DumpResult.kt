package org.kvxd.source2offset.export

import org.kvxd.source2offset.schema.ModuleSchemaDump

data class DumpResult(
    val timestamp: String,
    val interfaces: Map<String, List<InterfaceEntry>>,
    val offsets: Map<String, List<OffsetEntry>>,
    val schemas: List<ModuleSchemaDump>,
    val symbols: Map<String, List<ElfSymbolEntry>>,
    val runtimeRoots: List<RuntimeRootEntry>,
    val capabilities: List<CapabilityMessage>,
)
