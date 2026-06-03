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
actual fun processHasLaunchArgument(pid: Int, argument: String): Boolean? {
    val file = fopen("/proc/$pid/cmdline", "rb") ?: return null
    return try {
        memScoped {
            val bytes = mutableListOf<Byte>()
            val buffer = allocArray<ByteVar>(4096)
            while (true) {
                val read = fread(buffer, 1.convert(), 4096.convert(), file).toInt()
                if (read <= 0) break
                for (i in 0 until read) bytes += buffer[i]
            }
            nullSeparatedStrings(bytes).any { it == argument }
        }
    } finally {
        fclose(file)
    }
}

private fun nullSeparatedStrings(bytes: List<Byte>): List<String> {
    val values = mutableListOf<String>()
    var start = 0
    for (i in bytes.indices) {
        if (bytes[i] == 0.toByte()) {
            if (i > start) values += bytes.subList(start, i).toByteArray().decodeToString()
            start = i + 1
        }
    }
    if (start < bytes.size) values += bytes.subList(start, bytes.size).toByteArray().decodeToString()
    return values
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
