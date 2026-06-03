package org.kvxd.source2offset.core

import kotlinx.cinterop.*
import platform.posix.*

actual val currentPlatform: PlatformInfo = PlatformInfo(
    processName = "cs2.exe",
    moduleKindName = "PE",
    supportsElfSymbols = false,
    supportsLiveInterfaces = true,
    supportsLiveSchemas = true,
    supportsRuntimeRoots = false,
    coreSymbolModules = emptySet(),
)

actual fun parseMemoryMap(pid: Int): List<MemoryMapping> {
    val command = powershell(
        "Get-Process -Id $pid | Select-Object -ExpandProperty Modules | ForEach-Object { " +
                "Write-Output ([string]::Format('{0}`t{1}`t{2}`t{3}', " +
                "${'$'}_.ModuleName, ${'$'}_.FileName, ${'$'}_.BaseAddress.ToInt64(), ${'$'}_.ModuleMemorySize)) }"
    )

    return readCommandLines(command).mapNotNull { line ->
        val parts = line.split('\t')
        if (parts.size < 4) return@mapNotNull null
        val base = parts[2].toLongOrNull() ?: return@mapNotNull null
        val size = parts[3].toLongOrNull() ?: return@mapNotNull null
        MemoryMapping(
            start = base,
            end = base + size,
            permissions = "r-xp",
            fileOffset = 0,
            device = "windows",
            inode = 0u,
            path = parts[1],
        )
    }
}

actual fun findPidsByMapsKeyword(keyword: String): List<Int> =
    enumerateProcessIds().filter { pid ->
        runCatching { parseMemoryMap(pid).any { it.path.contains(keyword, ignoreCase = true) } }
            .getOrDefault(false)
    }

actual fun filterGameModulesForPlatform(modules: List<Module>, gameDir: String?): Pair<String?, List<Module>> {
    val normalizedGameDir = gameDir?.normalizeWindowsPath()
    val root = normalizedGameDir ?: modules.firstOrNull { module ->
        GAME_PATH_MARKERS.any { marker -> marker in module.path.normalizeWindowsPath() }
    }?.path?.let { path ->
        val normalized = path.normalizeWindowsPath()
        val marker = "Counter-Strike Global Offensive/game"
        val at = normalized.indexOf(marker)
        if (at >= 0) normalized.substring(0, at + marker.length) else normalized.substringBefore("/bin/win64/")
    }

    if (root == null) return null to emptyList()
    val gameModules = modules.filter { module ->
        module.path.normalizeWindowsPath().startsWith(root, ignoreCase = true) &&
                module.name.endsWith(".dll", ignoreCase = true)
    }
    return root to gameModules
}

internal fun findPidByExecutableName(name: String): Int? {
    val stem = name.substringBeforeLast(".exe")
    val command = powershell("Get-Process -Name '$stem' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Id")
    return readCommandLines(command).firstOrNull()?.trim()?.toIntOrNull()
}

private fun enumerateProcessIds(): List<Int> =
    readCommandLines(powershell("Get-Process | Select-Object -ExpandProperty Id"))
        .mapNotNull { it.trim().toIntOrNull() }

private fun powershell(script: String): String =
    "powershell -NoProfile -ExecutionPolicy Bypass -Command \"& { $script }\""

@OptIn(ExperimentalForeignApi::class)
internal fun readCommandLines(command: String): List<String> {
    val lines = mutableListOf<String>()
    memScoped {
        val pipe = popen?.invoke(command.cstr.ptr, "r".cstr.ptr) ?: return emptyList()
        try {
            val buffer = allocArray<ByteVar>(8192)
            while (fgets(buffer, 8191, pipe) != null) {
                val line = buffer.toKString().trimEnd('\r', '\n')
                if (line.isNotBlank()) lines += line
            }
        } finally {
            pclose?.invoke(pipe)
        }
    }
    return lines
}

private fun String.normalizeWindowsPath(): String =
    replace('\\', '/')

private val GAME_PATH_MARKERS = listOf(
    "Counter-Strike Global Offensive/game",
    "game/bin/win64",
    "game/csgo/bin/win64",
)
