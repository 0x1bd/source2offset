package org.kvxd.source2offset.engine

internal sealed interface Extraction {
    data class RipRelative(val displacementOffset: Int, val bytesAfterDisplacement: Int = 4) : Extraction
    data class I8(val valueOffset: Int) : Extraction
    data class I32(val valueOffset: Int) : Extraction
    data class CallTargetRipRelative(
        val callDisplacementOffset: Int,
        val targetDisplacementOffset: Int,
        val targetBytesAfterDisplacement: Int = 4,
    ) : Extraction
}

internal data class GlobalRule(
    val name: String,
    val moduleName: String,
    val pattern: String,
    val access: String,
    val extraction: Extraction,
)

internal data class MemberRule(
    val name: String,
    val moduleName: String,
    val pattern: String,
    val extraction: Extraction,
)
