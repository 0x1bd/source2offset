package org.kvxd.source2offset.core

import kotlinx.cinterop.*
import platform.posix.*

private fun parseMapsLine(line: String): MemoryMapping? {
    val parts = line.trimEnd().trimStart().split(Regex("\\s+"), limit = 6)
    if (parts.size < 5) return null

    val range = parts[0].split('-', limit = 2)
    if (range.size != 2) return null

    val start = range[0].toULongOrNull(16)?.toLong() ?: return null
    val end = range[1].toULongOrNull(16)?.toLong() ?: return null
    val perms = parts[1]
    if (perms.length != 4) return null
    val offset = parts[2].toULongOrNull(16)?.toLong() ?: return null
    val device = parts[3]
    val inode = parts[4].toULongOrNull() ?: return null
    val path = parts.getOrElse(5) { "" }

    return MemoryMapping(start, end, perms, offset, device, inode, path)
}

@OptIn(ExperimentalForeignApi::class)
actual fun parseMemoryMap(pid: Int): List<MemoryMapping> {
    val path = "/proc/$pid/maps"
    val file = fopen(path, "r") ?: error("Cannot open $path: ${strerror(errno)?.toKString() ?: "unknown"}")
    val result = mutableListOf<MemoryMapping>()
    try {
        memScoped {
            val line = allocArray<ByteVar>(16 * 1024)
            while (fgets(line, 16 * 1024 - 1, file) != null) {
                parseMapsLine(line.toKString())?.let(result::add)
            }
        }
    } finally {
        fclose(file)
    }
    return result
}

@OptIn(ExperimentalForeignApi::class)
actual fun findPidsByMapsKeyword(keyword: String): List<Int> {
    val result = mutableListOf<Int>()
    val dir = opendir("/proc") ?: return result
    try {
        while (true) {
            val entry = readdir(dir) ?: break
            val pid = entry.pointed.d_name.toKString().toIntOrNull() ?: continue
            val f = fopen("/proc/$pid/maps", "r") ?: continue
            var found = false
            try {
                memScoped {
                    val line = allocArray<ByteVar>(16 * 1024)
                    while (!found && fgets(line, 16 * 1024 - 1, f) != null) {
                        found = keyword in line.toKString()
                    }
                }
            } finally {
                fclose(f)
            }
            if (found) result += pid
        }
    } finally {
        closedir(dir)
    }
    return result
}
