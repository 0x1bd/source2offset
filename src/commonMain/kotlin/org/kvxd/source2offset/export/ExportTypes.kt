package org.kvxd.source2offset.export

data class InterfaceEntry(
    val name: String,
    val moduleName: String,
    val rva: Long,
    val address: Long,
)

data class ElfSymbolEntry(
    val moduleName: String,
    val name: String,
    val rva: Long,
    val size: Long,
    val kind: String,
    val binding: String,
    val table: String,
)

data class RuntimeRootEntry(
    val name: String,
    val sourceModule: String,
    val sourceInterface: String,
    val sourceInterfaceRva: Long,
    val memberOffset: Long,
    val targetType: String,
    val targetAddress: Long,
)

data class OffsetEntry(
    val name: String,
    val moduleName: String,
    val rva: Long,
    val access: String,
    val discovery: String,
    val note: String = "",
)

fun normaliseModuleName(name: String): String {
    var n = name.lowercase()
    if (n.startsWith("lib")) n = n.substring(3)
    val soIndex = n.indexOf(".so")
    if (soIndex >= 0) n = n.substring(0, soIndex)
    if (n.endsWith(".dll")) n = n.substringBeforeLast(".dll")
    return n.replace(Regex("[^a-z0-9_]"), "_")
}
