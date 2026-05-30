
package org.kvxd.source2offset.core

class MemReader(val handle: ProcessHandle) {

    fun readBytes(addr: Long, size: Int): ByteArray = handle.readBytes(addr, size)

    fun readU8(addr: Long): Int = handle.readBytes(addr, 1)[0].toInt() and 0xFF

    fun readU16(addr: Long): Int {
        val b = handle.readBytes(addr, 2)
        return (b[0].toInt() and 0xFF) or ((b[1].toInt() and 0xFF) shl 8)
    }

    fun readU32(addr: Long): Long {
        val b = handle.readBytes(addr, 4)
        return (b[0].toLong() and 0xFF) or
               ((b[1].toLong() and 0xFF) shl 8) or
               ((b[2].toLong() and 0xFF) shl 16) or
               ((b[3].toLong() and 0xFF) shl 24)
    }

    fun readI32(addr: Long): Int = handle.readInt(addr)

    fun readU64(addr: Long): Long = handle.readLong(addr)

    fun readPtr(addr: Long): Long = readU64(addr)

    fun readString(addr: Long, maxLen: Int = 256): String = handle.readString(addr, maxLen)

    fun deref(base: Long, offsets: List<Long>): Long {
        var addr = base
        for (off in offsets) {
            addr = readPtr(addr + off)
            if (addr == 0L) return 0L
        }
        return addr
    }
}
