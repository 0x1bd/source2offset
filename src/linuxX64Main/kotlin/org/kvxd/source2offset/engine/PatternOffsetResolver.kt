package org.kvxd.source2offset.engine

import org.kvxd.source2offset.core.Module
import org.kvxd.source2offset.elf.ElfParser
import org.kvxd.source2offset.export.OffsetEntry

internal class PatternOffsetResolver(
    private val modules: List<Module>,
    private val readFile: (String) -> ByteArray,
    private val collector: OffsetCollector,
) {
    fun resolveGlobals(rules: Iterable<GlobalRule>) {
        rules.forEach(::resolveGlobal)
    }

    fun resolveMembers(rules: Iterable<MemberRule>) {
        rules.forEach(::resolveMember)
    }

    private fun resolveGlobal(rule: GlobalRule) {
        val module = modules.firstOrNull { it.name == rule.moduleName } ?: return
        val image = runCatching { readFile(module.path) }.getOrNull() ?: return
        val elf = runCatching { ElfParser(image) }.getOrNull() ?: return
        val hits = BytePattern(rule.pattern).findAll(image)
        if (hits.size != 1) {
            return
        }

        val hit = hits.single()
        val instructionRva = elf.fileOffsetToRva(hit.toLong()) ?: return
        val rva = when (val extraction = rule.extraction) {
            is Extraction.RipRelative -> {
                val displacement = readI32(image, hit + extraction.displacementOffset)
                instructionRva + extraction.displacementOffset + extraction.bytesAfterDisplacement + displacement
            }

            is Extraction.I8 -> image[hit + extraction.valueOffset].toLong() and 0xFF
            is Extraction.I32 -> readI32(image, hit + extraction.valueOffset).toLong()
            is Extraction.CallTargetRipRelative -> {
                val callDisplacement = readI32(image, hit + extraction.callDisplacementOffset)
                val targetRva = instructionRva + extraction.callDisplacementOffset + 4 + callDisplacement
                val targetFileOffset = elf.rvaToFileOffset(targetRva)?.toInt() ?: return
                val targetDisplacement = readI32(image, targetFileOffset + extraction.targetDisplacementOffset)
                targetRva + extraction.targetDisplacementOffset + extraction.targetBytesAfterDisplacement + targetDisplacement
            }
        }

        collector.emit(
            OffsetEntry(
                name = rule.name,
                moduleName = module.name,
                rva = rva,
                access = rule.access,
                discovery = "linux_pattern",
            )
        )
    }

    private fun resolveMember(rule: MemberRule) {
        val module = modules.firstOrNull { it.name == rule.moduleName } ?: return
        val image = runCatching { readFile(module.path) }.getOrNull() ?: return
        val hits = BytePattern(rule.pattern).findAll(image)
        if (hits.size != 1) {
            return
        }

        val hit = hits.single()
        val offset = when (val extraction = rule.extraction) {
            is Extraction.I8 -> image[hit + extraction.valueOffset].toLong() and 0xFF
            is Extraction.I32 -> readI32(image, hit + extraction.valueOffset).toLong()
            is Extraction.RipRelative, is Extraction.CallTargetRipRelative -> return
        }

        collector.emit(
            OffsetEntry(
                name = rule.name,
                moduleName = module.name,
                rva = offset,
                access = "member_offset",
                discovery = "linux_pattern",
            )
        )
    }
}
