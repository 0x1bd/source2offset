package org.kvxd.source2offset.engine.rtti

data class RuntimeTypeInfo(
    val objectAddress: Long,
    val vtableAddress: Long,
    val typeInfoAddress: Long,
    val rawName: String,
    val typeName: String,
)