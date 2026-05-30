package org.kvxd.source2offset.core

import kotlinx.cinterop.*
import platform.posix.*

@OptIn(ExperimentalForeignApi::class)
actual class ProcessHandle actual constructor(private val pid: Int) : AutoCloseable {

    init {
        if (kill(pid.convert(), 0) != 0) {
            val message = strerror(errno)?.toKString() ?: "unknown"
            error("Cannot access pid=$pid: $message")
        }
    }

    actual override fun close() = Unit

    actual fun readBytes(address: Long, size: Int): ByteArray {
        require(size >= 0) { "Negative read size: $size" }
        if (size == 0) return ByteArray(0)

        val bytes = ByteArray(size)
        bytes.usePinned { pinned ->
            memScoped {
                var completed = 0
                while (completed < size) {
                    val local = allocArray<LongVar>(2)
                    val remote = allocArray<LongVar>(2)
                    val remaining = size - completed

                    local[0] = pinned.addressOf(completed).toLong()
                    local[1] = remaining.toLong()
                    remote[0] = address + completed.toLong()
                    remote[1] = remaining.toLong()

                    val amount = syscall(
                        SYS_PROCESS_VM_READV,
                        pid,
                        local,
                        1L,
                        remote,
                        1L,
                        0L,
                    ).toLong()

                    if (amount <= 0L) {
                        val message = strerror(errno)?.toKString() ?: "unknown"
                        val hint = if (errno == EPERM) {
                            " (process_vm_readv denied; check kernel.yama.ptrace_scope or run with the same ptrace permissions that allow GDB attach)"
                        } else {
                            ""
                        }
                        error(
                            "process_vm_readv(${(address + completed).hexAddress()}, " +
                                "${remaining} bytes) failed after $completed/$size bytes: $message$hint"
                        )
                    }

                    completed += amount.toInt()
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

    companion object {
        private const val SYS_PROCESS_VM_READV = 310L
    }
}
