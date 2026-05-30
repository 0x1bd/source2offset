package org.kvxd.source2offset.core

data class MemoryMapping(
    val start: Long,
    val end: Long,
    val permissions: String,
    val fileOffset: Long,
    val device: String,
    val inode: ULong,
    val path: String,
) {
    val readable: Boolean get() = permissions.getOrNull(0) == 'r'
    val writable: Boolean get() = permissions.getOrNull(1) == 'w'
    val executable: Boolean get() = permissions.getOrNull(2) == 'x'
    val privateMapping: Boolean get() = permissions.getOrNull(3) == 'p'
    val size: ULong get() = end.toULong() - start.toULong()

    fun contains(address: Long): Boolean {
        val value = address.toULong()
        return value >= start.toULong() && value < end.toULong()
    }
}

data class Module(
    val name: String,
    val path: String,
    val base: Long,
    val start: Long,
    val end: Long,
    val mappings: List<MemoryMapping>,
) {
    val size: ULong get() = end.toULong() - start.toULong()
    fun addressOf(rva: Long): Long = base + rva
    fun rvaOf(address: Long): Long = address - base
}

expect fun parseMemoryMap(pid: Int): List<MemoryMapping>
expect fun findPidsByMapsKeyword(keyword: String): List<Int>

fun parseModuleMap(pid: Int): List<Module> =
    parseMemoryMap(pid)
        .asSequence()
        .filter { '/' in it.path }
        .groupBy { it.path.removeSuffix(" (deleted)") }
        .map { (path, entries) ->
            val ordered = entries.sortedWith(compareBy { it.start.toULong() })
            val base = entries
                .map { it.start - it.fileOffset }
                .minWithOrNull(compareBy { it.toULong() })!!
            Module(
                name = path.substringAfterLast('/'),
                path = path,
                base = base,
                start = ordered.first().start,
                end = ordered.last().end,
                mappings = ordered,
            )
        }
        .sortedWith(compareBy { it.base.toULong() })

fun List<Module>.findByKeyword(keyword: String): Module? =
    firstOrNull { it.name.contains(keyword, ignoreCase = true) }

private val GAME_PATH_MARKERS = listOf(
    "Counter-Strike Global Offensive/game",
    "game/bin/linuxsteamrt64",
    "game/csgo/bin/linuxsteamrt64",
)

fun List<Module>.filterGameModules(gameDir: String? = null): Pair<String?, List<Module>> {
    val root = gameDir ?: firstOrNull { module ->
        GAME_PATH_MARKERS.any { marker -> marker in module.path }
    }?.path?.let { path ->
        val marker = "Counter-Strike Global Offensive/game"
        val at = path.indexOf(marker)
        if (at >= 0) path.substring(0, at + marker.length) else path.substringBefore("/bin/linuxsteamrt64/")
    }

    if (root == null) return null to emptyList()
    return root to filter { it.path.startsWith(root) && it.name.endsWith(".so") }
}

fun Long.hexAddress(): String = "0x${toULong().toString(16)}"
