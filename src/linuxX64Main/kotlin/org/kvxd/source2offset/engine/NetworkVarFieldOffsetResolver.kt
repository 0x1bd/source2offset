package org.kvxd.source2offset.engine

import org.kvxd.source2offset.core.Module
import org.kvxd.source2offset.elf.ElfParser
import org.kvxd.source2offset.export.OffsetEntry

internal class NetworkVarFieldOffsetResolver(
    private val modules: List<Module>,
    private val readFile: (String) -> ByteArray,
    private val collector: OffsetCollector,
) {
    fun resolve() {
        val client = modules.firstOrNull { it.name == "libclient.so" } ?: return
        val image = runCatching { readFile(client.path) }.getOrNull() ?: return
        val elf = runCatching { ElfParser(image) }.getOrNull() ?: return
        val fields = extractNetworkVarFields(image)
        val fieldsByName = fields.groupBy { it.fieldName }
        val nameRvasByFieldName = findFieldNameRvas(image, elf, fieldsByName.keys)
        val fieldsByNameRva = nameRvasByFieldName
            .flatMap { (fieldName, nameRvas) ->
                val matchingFields = fieldsByName[fieldName].orEmpty()
                nameRvas.map { nameRva -> nameRva to matchingFields }
            }
            .toMap()
        val offsetsByField = findNetworkFieldOffsets(image, fieldsByNameRva)

        for (field in fields) {
            val offset = chooseFieldOffset(offsetsByField[field].orEmpty()) ?: continue
            collector.emit(
                OffsetEntry(
                    name = "${field.className}_${field.fieldName}",
                    moduleName = client.name,
                    rva = offset.toLong(),
                    access = "member_offset",
                    discovery = "client_networkvar_metadata",
                )
            )
        }
    }

    private fun extractNetworkVarFields(image: ByteArray): List<NetworkVarField> =
        extractStringsContaining(image, NETWORK_VAR_PREFIX)
            .asSequence()
            .filter { NETWORK_VAR_PREFIX in it.value }
            .flatMap { parseNetworkVarFields(it.value).asSequence() }
            .distinct()
            .toList()

    private fun findFieldNameRvas(
        image: ByteArray,
        elf: ElfParser,
        fieldNames: Set<String>,
    ): Map<String, Set<Long>> {
        if (fieldNames.isEmpty()) return emptyMap()

        val namesByLength = fieldNames.groupBy { it.length }
            .mapValues { (_, names) -> names.toSet() }
        val rvasByName = mutableMapOf<String, MutableSet<Long>>()
        var start = 0
        var cursor = 0

        while (cursor <= image.size) {
            val ended = cursor == image.size || image[cursor] == 0.toByte()
            if (ended) {
                val length = cursor - start
                val candidates = namesByLength[length]
                if (candidates != null && image.isPrintableAscii(start, cursor)) {
                    val value = image.decodeToString(start, cursor)
                    if (value in candidates) {
                        val rva = elf.fileOffsetToRva(start.toLong())
                        if (rva != null) {
                            rvasByName.getOrPut(value) { mutableSetOf() } += rva
                        }
                    }
                }
                start = cursor + 1
            }
            cursor++
        }

        return rvasByName
    }

    private fun findNetworkFieldOffsets(
        image: ByteArray,
        fieldsByNameRva: Map<Long, List<NetworkVarField>>,
    ): Map<NetworkVarField, Set<Int>> {
        if (fieldsByNameRva.isEmpty()) return emptyMap()

        val minNameRva = fieldsByNameRva.keys.min()
        val maxNameRva = fieldsByNameRva.keys.max()
        val offsetsByField = mutableMapOf<NetworkVarField, MutableSet<Int>>()
        var at = 0

        while (at <= image.size - POINTER_SIZE) {
            val maybeNameRva = readU64(image, at)
            if (maybeNameRva in minNameRva..maxNameRva) {
                val fields = fieldsByNameRva[maybeNameRva]
                if (fields != null) {
                    val schemaOffset = readCandidateFieldOffset(image, at + 0x10)
                    for (field in fields) {
                        val offsets = offsetsByField.getOrPut(field) { mutableSetOf() }
                        if (schemaOffset != null) offsets += schemaOffset
                    }
                }
            }

            at += POINTER_SIZE.toInt()
        }

        return offsetsByField
    }

    private fun chooseFieldOffset(offsets: Set<Int>): Int? {
        val candidates = offsets
            .distinct()
            .filter { it in 0..MAX_NETWORK_FIELD_OFFSET }

        return candidates
            .filter { it >= MIN_NETWORK_FIELD_OFFSET }
            .singleOrNull()
            ?: candidates.singleOrNull()
    }

    private fun readCandidateFieldOffset(image: ByteArray, at: Int): Int? {
        if (at < 0 || at + 4 > image.size) return null
        return readI32(image, at).takeIf { it in 0..MAX_NETWORK_FIELD_OFFSET }
    }

    private fun parseNetworkVarFields(value: String): List<NetworkVarField> {
        val fields = mutableListOf<NetworkVarField>()
        var start = 0

        while (start < value.length) {
            val marker = value.indexOf('N', start)
            if (marker < 0) break

            val parsedClass = parseLengthPrefixedToken(value, marker + 1)
            if (parsedClass == null) {
                start = marker + 1
                continue
            }

            val parsedField = parseLengthPrefixedToken(value, parsedClass.nextIndex)
            if (parsedField == null) {
                start = marker + 1
                continue
            }

            if (parsedField.token.startsWith(NETWORK_VAR_PREFIX)) {
                val fieldName = parsedField.token.removePrefix(NETWORK_VAR_PREFIX)
                if (fieldName.isUsefulNetworkFieldName()) {
                    fields += NetworkVarField(parsedClass.token, fieldName)
                }
            }

            start = parsedClass.nextIndex
        }

        return fields
    }

    private fun parseLengthPrefixedToken(value: String, start: Int): ParsedToken? {
        var cursor = start
        if (cursor >= value.length || !value[cursor].isDigit()) return null

        var length = 0
        while (cursor < value.length && value[cursor].isDigit()) {
            length = length * 10 + (value[cursor].code - '0'.code)
            cursor++
        }

        if (length <= 0 || cursor + length > value.length) return null
        return ParsedToken(
            token = value.substring(cursor, cursor + length),
            nextIndex = cursor + length,
        )
    }

    private fun String.isUsefulNetworkFieldName(): Boolean =
        isNotBlank() &&
                length <= 128 &&
                first().let { it == '_' || it.isLetter() } &&
                all { it == '_' || it.isLetterOrDigit() }

    private fun extractStringsContaining(image: ByteArray, needle: String): List<AsciiString> {
        val needleBytes = needle.encodeToByteArray()
        val stringsByOffset = mutableMapOf<Int, String>()
        var searchStart = 0

        while (searchStart <= image.size - needleBytes.size) {
            val hit = image.indexOfBytes(needleBytes, searchStart)
            if (hit < 0) break

            var start = hit
            while (start > 0 && image[start - 1] != 0.toByte()) start--

            var end = hit + needleBytes.size
            while (end < image.size && image[end] != 0.toByte()) end++

            if (image.isPrintableAscii(start, end)) {
                stringsByOffset[start] = image.decodeToString(start, end)
            }

            searchStart = hit + 1
        }

        return stringsByOffset
            .map { (fileOffset, value) -> AsciiString(fileOffset, value) }
            .sortedBy { it.fileOffset }
    }

    private data class AsciiString(
        val fileOffset: Int,
        val value: String,
    )

    private data class ParsedToken(
        val token: String,
        val nextIndex: Int,
    )

    private data class NetworkVarField(
        val className: String,
        val fieldName: String,
    )

    private companion object {
        private const val MIN_NETWORK_FIELD_OFFSET = 0x10
        private const val MAX_NETWORK_FIELD_OFFSET = 0x100000
        private const val NETWORK_VAR_PREFIX = "NetworkVar_"
    }
}
