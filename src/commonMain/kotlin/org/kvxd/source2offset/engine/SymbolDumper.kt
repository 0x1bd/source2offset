package org.kvxd.source2offset.engine

import org.kvxd.source2offset.core.Module
import org.kvxd.source2offset.elf.ElfParser
import org.kvxd.source2offset.export.ElfSymbolEntry
import org.kvxd.source2offset.export.normaliseModuleName

class SymbolDumper(private val readFile: (String) -> ByteArray) {
    fun dump(modules: List<Module>, log: (String) -> Unit = {}): Map<String, List<ElfSymbolEntry>> {
        val result = mutableMapOf<String, List<ElfSymbolEntry>>()
        for (module in modules) {
            val bytes = runCatching { readFile(module.path) }.getOrNull() ?: continue
            val elf = runCatching { ElfParser(bytes) }.getOrNull() ?: continue
            val symbols = elf.symbols
                .filter { it.defined && it.name.isNotBlank() }
                .map { symbol ->
                    ElfSymbolEntry(
                        moduleName = module.name,
                        name = symbol.name,
                        rva = symbol.value,
                        size = symbol.size,
                        kind = when {
                            symbol.function -> "function"
                            symbol.obj -> "object"
                            else -> "other"
                        },
                        binding = when (symbol.binding) {
                            ElfParser.STB_GLOBAL -> "global"
                            ElfParser.STB_WEAK -> "weak"
                            else -> "local"
                        },
                        table = symbol.table,
                    )
                }
                .distinctBy { listOf(it.name, it.rva, it.kind) }
                .sortedWith(compareBy({ it.name }, { it.rva }))
            if (symbols.isNotEmpty()) {
                result[normaliseModuleName(module.name)] = symbols
                log("  [symbols] ${module.name} -> ${symbols.size} named symbol(s)")
            }
        }
        return result
    }
}
