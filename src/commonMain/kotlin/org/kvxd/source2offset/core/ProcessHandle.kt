package org.kvxd.source2offset.core

expect class ProcessHandle(pid: Int) : AutoCloseable {

    fun readBytes(address: Long, size: Int): ByteArray

    fun readLong(address: Long): Long

    fun readInt(address: Long): Int

    fun readString(address: Long, maxLen: Int = 256): String

    override fun close()
}
