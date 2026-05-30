package org.kvxd.source2offset.engine.rtti

import org.kvxd.source2offset.core.MemReader
import org.kvxd.source2offset.core.MemoryMapping

class RttiInspector(
    private val mem: MemReader,
    private val mappings: List<MemoryMapping>,
) {
    fun inspectObject(address: Long): RuntimeTypeInfo? {
        if (!isReadable(address, 8)) return null
        val vtable = runCatching { mem.readPtr(address) }.getOrNull() ?: return null
        if (vtable == 0L || !isReadable(vtable - 16L, 24)) return null

        val typeInfo = runCatching { mem.readPtr(vtable - 8L) }.getOrNull() ?: return null
        val firstVirtualFunction = runCatching { mem.readPtr(vtable) }.getOrNull() ?: return null
        if (typeInfo == 0L || !isReadable(typeInfo, 16) || !isExecutable(firstVirtualFunction)) return null

        val namePointer = runCatching { mem.readPtr(typeInfo + 8L) }.getOrNull() ?: return null
        if (namePointer == 0L || !isReadable(namePointer, 1)) return null
        val rawName = runCatching { mem.readString(namePointer, 256) }.getOrNull().orEmpty()
        if (!looksLikeItaniumName(rawName)) return null

        return RuntimeTypeInfo(
            objectAddress = address,
            vtableAddress = vtable,
            typeInfoAddress = typeInfo,
            rawName = rawName,
            typeName = demangleSimpleItaniumName(rawName),
        )
    }

    private fun isReadable(address: Long, size: Int): Boolean {
        val end = address + size - 1L
        return mappings.any { it.readable && it.contains(address) && it.contains(end) }
    }

    private fun isExecutable(address: Long): Boolean = mappings.any { it.executable && it.contains(address) }

    private fun looksLikeItaniumName(name: String): Boolean {
        if (name.isBlank() || name.length > 255) return false
        if (!name.all { it.isLetterOrDigit() || it == '_' || it == 'N' || it == 'E' }) return false
        return name.first().isDigit() || (name.first() == 'N' && name.last() == 'E')
    }

    private fun demangleSimpleItaniumName(raw: String): String {
        var source = raw
        var nested = false
        if (source.startsWith('N') && source.endsWith('E')) {
            nested = true
            source = source.substring(1, source.length - 1)
        }
        val names = mutableListOf<String>()
        var index = 0
        while (index < source.length) {
            val digitStart = index
            while (index < source.length && source[index].isDigit()) index++
            if (digitStart == index) return raw
            val length = source.substring(digitStart, index).toIntOrNull() ?: return raw
            if (length <= 0 || index + length > source.length) return raw
            names += source.substring(index, index + length)
            index += length
        }
        if (names.isEmpty()) return raw
        return if (nested || names.size > 1) names.joinToString("::") else names.single()
    }
}