package org.kvxd.source2offset.core

import kotlinx.cinterop.*
import platform.windows.*

@OptIn(ExperimentalForeignApi::class)
actual class ProcessHandle actual constructor(private val pid: Int) : AutoCloseable {
    private val handle: HANDLE? = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION.toUInt() or PROCESS_VM_READ.toUInt(),
        0,
        pid.convert(),
    )

    init {
        if (handle == null) {
            error("OpenProcess($pid) failed: ${GetLastError()}")
        }
    }

    actual override fun close() {
        CloseHandle(handle)
    }

    actual fun readBytes(address: Long, size: Int): ByteArray {
        require(size >= 0) { "Negative read size: $size" }
        if (size == 0) return ByteArray(0)

        val bytes = ByteArray(size)
        bytes.usePinned { pinned ->
            memScoped {
                val read = alloc<SIZE_TVar>()
                val ok = ReadProcessMemory(
                    handle,
                    address.toCPointer(),
                    pinned.addressOf(0),
                    size.convert(),
                    read.ptr,
                )
                if (ok == 0 || read.value.toLong() != size.toLong()) {
                    error("ReadProcessMemory(${address.hexAddress()}, $size bytes) failed: ${GetLastError()}")
                }
            }
        }
        return bytes
    }

    actual fun readLong(address: Long): Long {
        val bytes = readBytes(address, 8)
        var value = 0L
        for (i in 0 until 8) value = value or ((bytes[i].toLong() and 0xFF) shl (i * 8))
        return value
    }

    actual fun readInt(address: Long): Int {
        val bytes = readBytes(address, 4)
        return (bytes[0].toInt() and 0xFF) or
                ((bytes[1].toInt() and 0xFF) shl 8) or
                ((bytes[2].toInt() and 0xFF) shl 16) or
                (bytes[3].toInt() shl 24)
    }

    actual fun readString(address: Long, maxLen: Int): String {
        require(maxLen in 1..1_048_576) { "Invalid string limit: $maxLen" }
        val bytes = readBytes(address, maxLen)
        val end = bytes.indexOf(0.toByte()).takeIf { it >= 0 } ?: bytes.size
        return bytes.decodeToString(0, end)
    }
}
