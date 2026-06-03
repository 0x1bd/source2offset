package org.kvxd.source2offset.cli

import kotlinx.cinterop.*
import org.kvxd.source2offset.core.findPidByExecutableName
import org.kvxd.source2offset.core.readCommandLines
import platform.posix.*

actual fun findProcessPid(name: String): Int? = findPidByExecutableName(name)

actual fun processHasLaunchArgument(pid: Int, argument: String): Boolean? {
    val command = "powershell -NoProfile -ExecutionPolicy Bypass -Command \"& { " +
            "Get-CimInstance Win32_Process -Filter 'ProcessId = $pid' | " +
            "Select-Object -ExpandProperty CommandLine }\""
    val commandLine = readCommandLines(command).firstOrNull() ?: return null
    return splitWindowsCommandLine(commandLine).any { it == argument }
}

private fun splitWindowsCommandLine(commandLine: String): List<String> {
    val args = mutableListOf<String>()
    val current = StringBuilder()
    var inQuotes = false

    for (char in commandLine) {
        when {
            char == '"' -> inQuotes = !inQuotes
            char.isWhitespace() && !inQuotes -> {
                if (current.isNotEmpty()) {
                    args += current.toString()
                    current.clear()
                }
            }
            else -> current.append(char)
        }
    }

    if (current.isNotEmpty()) args += current.toString()
    return args
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
