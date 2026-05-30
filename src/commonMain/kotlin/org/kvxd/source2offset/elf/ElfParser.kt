package org.kvxd.source2offset.elf

class ElfParser(private val data: ByteArray) {

    companion object {
        private val MAGIC = byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())
        private const val PT_LOAD = 1L
        private const val SHT_SYMTAB = 2L
        private const val SHT_STRTAB = 3L
        private const val SHT_DYNSYM = 11L
        const val STT_NOTYPE = 0
        const val STT_OBJECT = 1
        const val STT_FUNC = 2
        const val STB_LOCAL = 0
        const val STB_GLOBAL = 1
        const val STB_WEAK = 2
    }

    init {
        require(data.size >= 64) { "Not a valid ELF64 file: file is too small" }
        require(data.sliceArray(0 until 4).contentEquals(MAGIC)) { "Not an ELF file" }
        require(data[4].toInt() == 2) { "Only ELF64 modules are supported" }
        require(data[5].toInt() == 1) { "Only little-endian ELF modules are supported" }
    }

    private val ePhoff: Long get() = readU64(0x20)
    private val eShoff: Long get() = readU64(0x28)
    private val ePhentsize: Int get() = readU16(0x36)
    private val ePhnum: Int get() = readU16(0x38)
    private val eShentsize: Int get() = readU16(0x3A)
    private val eShnum: Int get() = readU16(0x3C)
    private val eShstrndx: Int get() = readU16(0x3E)

    data class ProgramHeader(
        val type: Long,
        val flags: Long,
        val fileOffset: Long,
        val virtualAddress: Long,
        val fileSize: Long,
        val memorySize: Long,
    )

    data class Section(
        val nameOffset: Int,
        val type: Long,
        val flags: Long,
        val address: Long,
        val offset: Long,
        val size: Long,
        val link: Int,
        val entrySize: Long,
    )

    data class Symbol(
        val name: String,
        val value: Long,
        val size: Long,
        val binding: Int,
        val type: Int,
        val visibility: Int,
        val sectionIndex: Int,
        val table: String,
    ) {
        val defined: Boolean get() = sectionIndex != 0
        val exported: Boolean get() = defined && (binding == STB_GLOBAL || binding == STB_WEAK)
        val function: Boolean get() = type == STT_FUNC
        val obj: Boolean get() = type == STT_OBJECT
    }

    val programHeaders: List<ProgramHeader> by lazy {
        if (ePhoff <= 0L || ePhentsize <= 0 || ePhnum <= 0) return@lazy emptyList()
        (0 until ePhnum).mapNotNull { i ->
            val at = ePhoff + i.toLong() * ePhentsize
            if (!rangeAvailable(at, 56)) return@mapNotNull null
            ProgramHeader(
                type = readU32(at.toInt()),
                flags = readU32(at.toInt() + 4),
                fileOffset = readU64(at.toInt() + 8),
                virtualAddress = readU64(at.toInt() + 16),
                fileSize = readU64(at.toInt() + 32),
                memorySize = readU64(at.toInt() + 40),
            )
        }
    }

    val sections: List<Section> by lazy {
        if (eShoff <= 0L || eShentsize <= 0 || eShnum <= 0) return@lazy emptyList()
        (0 until eShnum).mapNotNull { i ->
            val at = eShoff + i.toLong() * eShentsize
            if (!rangeAvailable(at, 64)) return@mapNotNull null
            Section(
                nameOffset = readU32(at.toInt()).toInt(),
                type = readU32(at.toInt() + 0x04),
                flags = readU64(at.toInt() + 0x08),
                address = readU64(at.toInt() + 0x10),
                offset = readU64(at.toInt() + 0x18),
                size = readU64(at.toInt() + 0x20),
                link = readU32(at.toInt() + 0x28).toInt(),
                entrySize = readU64(at.toInt() + 0x38),
            )
        }
    }

    private val sectionNameTable: ByteArray by lazy {
        val section = sections.getOrNull(eShstrndx) ?: return@lazy byteArrayOf()
        sliceOrEmpty(section.offset, section.size)
    }

    fun sectionName(section: Section): String = cString(sectionNameTable, section.nameOffset)

    fun fileOffsetToRva(fileOffset: Long): Long? {
        val load = programHeaders.firstOrNull {
            it.type == PT_LOAD && fileOffset >= it.fileOffset && fileOffset < it.fileOffset + it.fileSize
        } ?: return null
        return load.virtualAddress + (fileOffset - load.fileOffset)
    }

    fun rvaToFileOffset(rva: Long): Long? {
        val load = programHeaders.firstOrNull {
            it.type == PT_LOAD && rva >= it.virtualAddress && rva < it.virtualAddress + it.fileSize
        } ?: return null
        return load.fileOffset + (rva - load.virtualAddress)
    }

    private fun stringTable(index: Int): ByteArray {
        val section = sections.getOrNull(index) ?: return byteArrayOf()
        return if (section.type == SHT_STRTAB) sliceOrEmpty(section.offset, section.size) else byteArrayOf()
    }

    private fun readSymbols(section: Section, tableName: String): List<Symbol> {
        if (section.entrySize <= 0 || section.size <= 0) return emptyList()
        val strings = stringTable(section.link)
        if (strings.isEmpty()) return emptyList()
        val count = section.size / section.entrySize
        return (0 until count).mapNotNull { i ->
            val at = section.offset + i * section.entrySize
            if (!rangeAvailable(at, 24)) return@mapNotNull null
            val name = cString(strings, readU32(at.toInt()).toInt())
            if (name.isEmpty()) return@mapNotNull null
            val info = data[at.toInt() + 4].toInt() and 0xFF
            Symbol(
                name = name,
                binding = info ushr 4,
                type = info and 0x0F,
                visibility = data[at.toInt() + 5].toInt() and 0x03,
                sectionIndex = readU16(at.toInt() + 6),
                value = readU64(at.toInt() + 8),
                size = readU64(at.toInt() + 16),
                table = tableName,
            )
        }
    }

    val dynamicSymbols: List<Symbol> by lazy {
        sections.filter { it.type == SHT_DYNSYM }.flatMap { readSymbols(it, ".dynsym") }
    }

    val staticSymbols: List<Symbol> by lazy {
        sections.filter { it.type == SHT_SYMTAB }.flatMap { readSymbols(it, ".symtab") }
    }

    val symbols: List<Symbol> by lazy {
        (dynamicSymbols + staticSymbols).distinctBy { listOf(it.name, it.value, it.size, it.type, it.sectionIndex) }
    }

    fun definedFunction(name: String): Symbol? =
        dynamicSymbols.firstOrNull { it.name == name && it.defined && it.function }
            ?: symbols.firstOrNull { it.name == name && it.defined && it.function }

    private fun cString(bytes: ByteArray, offset: Int): String {
        if (offset <= 0 || offset >= bytes.size) return ""
        var end = offset
        while (end < bytes.size && bytes[end] != 0.toByte()) end++
        return bytes.decodeToString(offset, end)
    }

    private fun rangeAvailable(offset: Long, size: Int): Boolean =
        offset >= 0L && offset <= data.size.toLong() - size

    private fun sliceOrEmpty(offset: Long, size: Long): ByteArray {
        if (offset < 0 || size < 0 || offset > Int.MAX_VALUE || size > Int.MAX_VALUE) return byteArrayOf()
        val start = offset.toInt()
        val end = start.toLong() + size
        if (start < 0 || end > data.size || end < start) return byteArrayOf()
        return data.sliceArray(start until end.toInt())
    }

    private fun readU16(offset: Int): Int =
        (data[offset].toInt() and 0xFF) or ((data[offset + 1].toInt() and 0xFF) shl 8)

    private fun readU32(offset: Int): Long =
        (data[offset].toLong() and 0xFF) or
            ((data[offset + 1].toLong() and 0xFF) shl 8) or
            ((data[offset + 2].toLong() and 0xFF) shl 16) or
            ((data[offset + 3].toLong() and 0xFF) shl 24)

    private fun readU64(offset: Int): Long =
        readU32(offset) or (readU32(offset + 4) shl 32)
}
