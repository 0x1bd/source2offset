package org.kvxd.source2offset.engine

import kotlinx.cinterop.*
import platform.posix.*

private val SAFE_INTERFACE_NAME = Regex("^[A-Za-z0-9_]+$")

@OptIn(ExperimentalForeignApi::class)
actual fun callCreateInterfaces(pid: Int, calls: List<RemoteInterfaceCall>): List<RemoteInterfaceResult> {
    if (calls.isEmpty()) return emptyList()

    val invalid = calls.filterNot { SAFE_INTERFACE_NAME.matches(it.interfaceName) }
    if (invalid.isNotEmpty()) {
        return calls.map { call ->
            if (call in invalid) {
                RemoteInterfaceResult(call, null, "interface name contains unsupported characters")
            } else {
                RemoteInterfaceResult(call, null, "batch cancelled because one request was invalid")
            }
        }
    }

    val scriptPath = "/tmp/source2offset-$pid-${getpid()}.gdb"
    val scriptText = buildString {
        appendLine("set pagination off")
        appendLine("set confirm off")
        appendLine("set print thread-events off")
        appendLine("attach $pid")

        appendLine("set scheduler-locking on")

        for ((index, call) in calls.withIndex()) {
            val address = "0x${call.createInterfaceAddress.toULong().toString(16)}"
            appendLine(
                "set \$s2o_$index = ((void* (*)(const char*, int*))$address)" +
                    "(\"${call.interfaceName}\", (int*)0)"
            )
            appendLine("printf \"S2O_RESULT|$index|%p\\n\", \$s2o_$index")
        }

        appendLine("set scheduler-locking off")
        appendLine("detach")
        appendLine("quit")
    }

    val script = fopen(scriptPath, "w")
        ?: return calls.map { RemoteInterfaceResult(it, null, "could not create temporary gdb script") }
    try {
        fputs(scriptText, script)
    } finally {
        fclose(script)
    }

    val gdbOutput = StringBuilder()
    val command = "gdb --nx --quiet --batch -x '$scriptPath' 2>&1"
    val pipe = popen(command, "r")
    if (pipe == null) {
        remove(scriptPath)
        return calls.map { RemoteInterfaceResult(it, null, "could not launch gdb") }
    }

    var gdbExitStatus = 0
    try {
        memScoped {
            val buffer = allocArray<ByteVar>(4096)
            while (fgets(buffer, 4095, pipe) != null) {
                gdbOutput.append(buffer.toKString())
            }
        }
    } finally {
        gdbExitStatus = pclose(pipe)
        remove(scriptPath)
    }

    val resolved = mutableMapOf<Int, Long>()
    val marker = Regex("S2O_RESULT\\|(\\d+)\\|(0x[0-9a-fA-F]+|\\(nil\\))")
    for (match in marker.findAll(gdbOutput.toString())) {
        val index = match.groupValues[1].toInt()
        val text = match.groupValues[2]
        if (text != "(nil)") {
            text.removePrefix("0x")
                .toULongOrNull(16)
                ?.toLong()
                ?.let { resolved[index] = it }
        }
    }

    val diagnostic = gdbOutput.toString()
        .lineSequence()
        .map { it.trim() }
        .filter { it.isNotBlank() }
        .toList()
        .takeLast(8)
        .joinToString(" | ")
        .ifBlank {
            if (gdbExitStatus == 0) "CreateInterface returned null"
            else "gdb exited without a result (status=$gdbExitStatus)"
        }

    return calls.mapIndexed { index, call ->
        val address = resolved[index]
        if (address != null) {
            RemoteInterfaceResult(call, address)
        } else {
            RemoteInterfaceResult(call, null, diagnostic)
        }
    }
}
