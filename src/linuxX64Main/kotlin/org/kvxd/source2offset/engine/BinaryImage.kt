package org.kvxd.source2offset.engine

internal const val POINTER_SIZE = 0x8L

internal fun readU64(bytes: ByteArray, at: Int): Long =
    (bytes[at].toLong() and 0xFF) or
            ((bytes[at + 1].toLong() and 0xFF) shl 8) or
            ((bytes[at + 2].toLong() and 0xFF) shl 16) or
            ((bytes[at + 3].toLong() and 0xFF) shl 24) or
            ((bytes[at + 4].toLong() and 0xFF) shl 32) or
            ((bytes[at + 5].toLong() and 0xFF) shl 40) or
            ((bytes[at + 6].toLong() and 0xFF) shl 48) or
            ((bytes[at + 7].toLong() and 0xFF) shl 56)

internal fun readI32(bytes: ByteArray, at: Int): Int =
    (bytes[at].toInt() and 0xFF) or
            ((bytes[at + 1].toInt() and 0xFF) shl 8) or
            ((bytes[at + 2].toInt() and 0xFF) shl 16) or
            (bytes[at + 3].toInt() shl 24)

internal fun ByteArray.isPrintableAscii(start: Int, endExclusive: Int): Boolean {
    for (index in start until endExclusive) {
        if (this[index].toInt() !in 0x20..0x7E) return false
    }
    return true
}

internal fun ByteArray.indexOfBytes(needle: ByteArray, startIndex: Int): Int {
    if (needle.isEmpty()) return startIndex.coerceAtMost(size)
    var at = startIndex.coerceAtLeast(0)
    val last = size - needle.size
    while (at <= last) {
        if (this[at] == needle[0]) {
            var matches = true
            for (index in 1 until needle.size) {
                if (this[at + index] != needle[index]) {
                    matches = false
                    break
                }
            }
            if (matches) return at
        }
        at++
    }
    return -1
}
