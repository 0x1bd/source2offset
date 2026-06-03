package org.kvxd.source2offset.engine

internal class BytePattern(pattern: String) {

    private val tokens: List<Int?> = pattern.trim().split(Regex("\\s+")).map { token ->
        if (token == "?" || token == "??") null else token.toInt(16)
    }
    private val anchor = tokens.indexOfFirst { it != null }.coerceAtLeast(0)

    fun findAll(bytes: ByteArray): List<Int> {
        if (tokens.isEmpty() || bytes.size < tokens.size) return emptyList()
        val results = mutableListOf<Int>()
        val last = bytes.size - tokens.size
        val expectedAnchor = tokens[anchor]
        var searchStart = 0

        while (searchStart <= last) {
            val at = if (expectedAnchor == null) {
                searchStart
            } else {
                val anchorHit = indexOfByte(bytes, expectedAnchor, searchStart + anchor)
                if (anchorHit < 0 || anchorHit - anchor > last) break
                anchorHit - anchor
            }

            var matches = true
            for (i in tokens.indices) {
                val expected = tokens[i] ?: continue
                if ((bytes[at + i].toInt() and 0xFF) != expected) {
                    matches = false
                    break
                }
            }
            if (matches) results += at
            searchStart = at + 1
        }
        return results
    }

    private fun indexOfByte(bytes: ByteArray, value: Int, startIndex: Int): Int {
        var at = startIndex.coerceAtLeast(0)
        val byteValue = value.toByte()
        while (at < bytes.size) {
            if (bytes[at] == byteValue) return at
            at++
        }
        return -1
    }
}
