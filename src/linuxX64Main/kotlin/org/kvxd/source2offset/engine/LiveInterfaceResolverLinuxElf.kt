package org.kvxd.source2offset.engine

import org.kvxd.source2offset.core.Module
import org.kvxd.source2offset.elf.ElfParser
import org.kvxd.source2offset.export.InterfaceEntry

actual class LiveInterfaceResolver actual constructor(
    private val modules: List<Module>,
    private val readFile: (String) -> ByteArray,
) {
    actual fun resolve(pid: Int, requests: List<InterfaceRequest>, log: (String) -> Unit): List<InterfaceEntry> {
        val calls = requests.mapNotNull { request ->
            val module = findModule(request.moduleKeyword)
            if (module == null) {
                log("WARN: No mapped module matched '${request.moduleKeyword}' for ${request.interfaceName}")
                return@mapNotNull null
            }

            val bytes = runCatching { readFile(module.path) }.getOrElse { error ->
                log("WARN: Cannot read ${module.path}: ${error.message}")
                return@mapNotNull null
            }
            val symbol = runCatching { ElfParser(bytes).definedFunction("CreateInterface") }.getOrNull()
            if (symbol == null) {
                log("WARN: ${module.name} does not expose a defined CreateInterface ELF symbol")
                return@mapNotNull null
            }

            RemoteInterfaceCall(
                moduleName = module.name,
                moduleBase = module.base,
                interfaceName = request.interfaceName,
                createInterfaceAddress = module.base + symbol.value,
            )
        }

        val results = callCreateInterfaces(pid, calls)
        return results.mapNotNull { result ->
            val address = result.instanceAddress
            if (address == null || address == 0L) {
                log("WARN: ${result.call.moduleName}!CreateInterface(${result.call.interfaceName}) failed: ${result.error ?: "returned null"}")
                return@mapNotNull null
            }
            val entry = InterfaceEntry(
                name = result.call.interfaceName,
                moduleName = result.call.moduleName,
                rva = address - result.call.moduleBase,
                address = address,
            )
            log("  [interface] ${entry.moduleName}:${entry.name} -> rva=0x${entry.rva.toULong().toString(16)}")
            entry
        }
    }

    private fun findModule(keyword: String): Module? {
        val stem = keyword.lowercase().removePrefix("lib").removeSuffix(".so")
        val expected = "lib$stem.so"
        return modules.firstOrNull { it.name.lowercase() == expected }
            ?: modules.firstOrNull { it.name.equals(keyword, ignoreCase = true) }
            ?: modules.firstOrNull {
                it.name.contains(keyword, ignoreCase = true) ||
                        it.path.contains(keyword, ignoreCase = true)
            }
    }
}
