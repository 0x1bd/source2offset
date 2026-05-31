package org.kvxd.source2offset.cli

import kotlinx.cinterop.*
import org.kvxd.source2offset.core.findPidsByMapsKeyword
import platform.posix.*

@OptIn(ExperimentalForeignApi::class)
actual fun findProcessPid(name: String): Int? {
    val candidates = linkedSetOf<Int>()
    listOf(
        "Counter-Strike Global Offensive/game/bin/linuxsteamrt64/cs2",
        "Counter-Strike Global Offensive/game/csgo/bin/linuxsteamrt64/libclient.so",
        "game/bin/linuxsteamrt64/libengine2.so",
        "game/bin/linuxsteamrt64/libSDL3.so.0",
    ).forEach { candidates += findPidsByMapsKeyword(it) }

    candidates.firstOrNull { pid ->
        readLink("/proc/$pid/exe")?.substringAfterLast('/') == "cs2"
    }?.let { return it }
    candidates.firstOrNull()?.let { return it }

    val dir = opendir("/proc") ?: return null
    try {
        while (true) {
            val entry = readdir(dir) ?: break
            val pid = entry.pointed.d_name.toKString().toIntOrNull() ?: continue
            val executable = readLink("/proc/$pid/exe") ?: continue
            if (executable.substringAfterLast('/') == name) return pid
        }
    } finally {
        closedir(dir)
    }
    return null
}

@OptIn(ExperimentalForeignApi::class)
private fun readLink(path: String): String? {
    val result = ByteArray(4096)
    return result.usePinned { buffer ->
        val length = readlink(path, buffer.addressOf(0), result.size.convert())
        if (length <= 0) null else result.decodeToString(0, length.toInt())
    }
}

@OptIn(ExperimentalForeignApi::class)
actual fun currentIsoTimestamp(): String = memScoped {
    val now = alloc<time_tVar>()
    time(now.ptr)
    val tm = alloc<tm>()
    gmtime_r(now.ptr, tm.ptr)
    val buffer = allocArray<ByteVar>(32)
    strftime(buffer, 31u, "%Y-%m-%dT%H:%M:%SZ", tm.ptr)
    buffer.toKString()
}

@OptIn(ExperimentalForeignApi::class)
actual fun readFileBytes(path: String): ByteArray {
    val file = fopen(path, "rb") ?: error("Cannot open $path: ${strerror(errno)?.toKString() ?: "unknown"}")
    try {
        check(fseek(file, 0, SEEK_END) == 0) { "Cannot seek $path" }
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
