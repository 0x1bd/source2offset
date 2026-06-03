package org.kvxd.source2offset.cli

import kotlinx.cinterop.*
import org.kvxd.source2offset.core.findPidByExecutableName
import platform.posix.*

actual fun findProcessPid(name: String): Int? = findPidByExecutableName(name)

@OptIn(ExperimentalForeignApi::class)
actual fun currentIsoTimestamp(): String = memScoped {
    val now = alloc<time_tVar>()
    time(now.ptr)
    val tm = alloc<tm>()
    gmtime_s(tm.ptr, now.ptr)
    val buffer = allocArray<ByteVar>(32)
    strftime(buffer, 31u, "%Y-%m-%dT%H:%M:%SZ", tm.ptr)
    buffer.toKString()
}

@OptIn(ExperimentalForeignApi::class)
actual fun readFileBytes(path: String): ByteArray {
    val file = fopen(path, "rb") ?: error("Cannot open $path")
    try {
        check(fseek(file, 0, platform.posix.SEEK_END) == 0) { "Cannot seek $path" }
        val size = ftell(file)
        check(size >= 0) { "Cannot determine length of $path" }
        rewind(file)
        val bytes = ByteArray(size.toInt())
        if (bytes.isNotEmpty()) {
            bytes.usePinned { pinned ->
                val read = fread(pinned.addressOf(0), 1.convert(), bytes.size.convert(), file).toInt()
                check(read == bytes.size) { "Partial read of $path: $read/${bytes.size}" }
            }
        }
        return bytes
    } finally {
        fclose(file)
    }
}
