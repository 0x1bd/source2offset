package org.kvxd.source2offset.engine

import org.kvxd.source2offset.core.Module
import org.kvxd.source2offset.core.ProcessHandle
import org.kvxd.source2offset.export.InterfaceEntry

actual fun callCreateInterfaces(pid: Int, calls: List<RemoteInterfaceCall>): List<RemoteInterfaceResult> =
    calls.map { RemoteInterfaceResult(it, null, "live Windows CreateInterface calls are not implemented") }

actual class LiveInterfaceResolver actual constructor(
    private val modules: List<Module>,
    @Suppress("unused") private val readFile: (String) -> ByteArray,
) {
    actual fun resolve(pid: Int, requests: List<InterfaceRequest>, log: (String) -> Unit): List<InterfaceEntry> {
        val requested = requests.associateBy { it.interfaceName }
        val entries = mutableListOf<InterfaceEntry>()

        val handle = runCatching { ProcessHandle(pid) }.getOrElse { error ->
            log("WARN: cannot open process for Windows InterfaceReg scan: ${error.message}")
            return emptyList()
        }
        try {
            for (module in modules) {
                val size = module.size.toLong()
                if (size <= 0L || size > Int.MAX_VALUE) continue
                val bytes = runCatching { handle.readBytes(module.base, size.toInt()) }.getOrNull() ?: continue
                val createInterfaceRva = findPeExportRva(bytes, "CreateInterface") ?: continue
                val listSlotRva = resolveRipRva(bytes, createInterfaceRva.toInt(), 3) ?: continue
                val listHead = runCatching { handle.readLong(module.base + listSlotRva) }.getOrNull() ?: continue

                var regPtr = listHead
                val seen = mutableSetOf<Long>()
                repeat(MAX_INTERFACES_PER_MODULE) {
                    if (regPtr == 0L || !seen.add(regPtr)) return@repeat
                    val entry = runCatching {
                        val createFn = handle.readLong(regPtr)
                        val namePtr = handle.readLong(regPtr + 0x8)
                        val next = handle.readLong(regPtr + 0x10)
                        val name = handle.readString(namePtr, 128)
                        val instanceAddress = resolveRipLive(handle, createFn, 3)
                        regPtr = next

                        if (name !in requested || instanceAddress == null) {
                            null
                        } else {
                            InterfaceEntry(
                                name = name,
                                moduleName = module.name,
                                rva = instanceAddress - module.base,
                                address = instanceAddress,
                            )
                        }
                    }.getOrNull()

                    if (entry != null) {
                        log("  [interface] ${entry.moduleName}:${entry.name} -> rva=0x${entry.rva.toULong().toString(16)}")
                        entries += entry
                    }
                }
            }
        } finally {
            handle.close()
        }

        val found = entries.mapTo(mutableSetOf()) { it.name }
        for (request in requests) {
            if (request.interfaceName !in found) {
                log("WARN: no Windows InterfaceReg matched ${request.interfaceName}")
            }
        }

        return entries
    }

    private companion object {
        private const val MAX_INTERFACES_PER_MODULE = 512
    }
}

private fun resolveRipLive(handle: ProcessHandle, address: Long, displacementOffset: Int): Long? =
    runCatching {
        val displacement = handle.readInt(address + displacementOffset)
        address + displacementOffset + 4 + displacement
    }.getOrNull()

private fun resolveRipRva(image: ByteArray, rva: Int, displacementOffset: Int): Long? {
    if (rva < 0 || rva + displacementOffset + 4 > image.size) return null
    val displacement = readI32(image, rva + displacementOffset)
    return rva.toLong() + displacementOffset + 4 + displacement
}

private fun findPeExportRva(image: ByteArray, exportName: String): Long? {
    if (image.size < 0x1000 || readU16(image, 0) != 0x5A4D) return null
    val nt = readI32(image, 0x3C)
    if (nt <= 0 || nt + 0x108 > image.size || readI32(image, nt) != 0x00004550) return null

    val optional = nt + 0x18
    if (readU16(image, optional) != 0x20B) return null
    val exportRva = readI32(image, optional + 0x70)
    if (exportRva <= 0 || exportRva + 0x28 > image.size) return null

    val numberOfNames = readI32(image, exportRva + 0x18)
    val functionsRva = readI32(image, exportRva + 0x1C)
    val namesRva = readI32(image, exportRva + 0x20)
    val ordinalsRva = readI32(image, exportRva + 0x24)
    if (numberOfNames < 0) return null

    for (index in 0 until numberOfNames) {
        val nameRva = readI32(image, namesRva + index * 4)
        val name = readCString(image, nameRva)
        if (name == exportName) {
            val ordinal = readU16(image, ordinalsRva + index * 2)
            return readI32(image, functionsRva + ordinal * 4).toLong()
        }
    }

    return null
}

private fun readCString(image: ByteArray, rva: Int): String? {
    if (rva < 0 || rva >= image.size) return null
    var end = rva
    while (end < image.size && image[end] != 0.toByte()) end++
    return image.decodeToString(rva, end)
}

private fun readU16(bytes: ByteArray, at: Int): Int =
    (bytes[at].toInt() and 0xFF) or ((bytes[at + 1].toInt() and 0xFF) shl 8)

private fun readI32(bytes: ByteArray, at: Int): Int =
    (bytes[at].toInt() and 0xFF) or
            ((bytes[at + 1].toInt() and 0xFF) shl 8) or
            ((bytes[at + 2].toInt() and 0xFF) shl 16) or
            (bytes[at + 3].toInt() shl 24)
