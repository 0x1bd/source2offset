package org.kvxd.source2offset.schema

import org.kvxd.source2offset.core.MemReader

class SchemaDumper(
    private val mem: MemReader,
    private val profiles: List<SchemaLayoutProfile> = SUPPORTED_SCHEMA_PROFILES,
) {
    fun dump(schemaSystemAddress: Long, log: (String) -> Unit = {}): List<ModuleSchemaDump> {
        val failures = mutableListOf<String>()

        for (profile in profiles) {
            val result = runCatching { dumpWithProfile(schemaSystemAddress, profile, log) }
            result.onSuccess { scopes ->
                log("  [schema] accepted ABI profile '${profile.name}'")
                return scopes
            }
            result.onFailure { error ->
                val message = error.message ?: error::class.simpleName ?: "unknown failure"
                failures += "${profile.name}: $message"
                log("  [schema] rejected ABI profile '${profile.name}': $message")
            }
        }

        error(
            "SchemaSystem was resolved, but no supported ABI profile produced reflected fields. " +
                failures.joinToString(" | ")
        )
    }

    private fun dumpWithProfile(
        schemaSystemAddress: Long,
        profile: SchemaLayoutProfile,
        log: (String) -> Unit,
    ): List<ModuleSchemaDump> {
        val scopeCount = mem.readI32(schemaSystemAddress + profile.typeScopesCount)
        val scopesPtr = mem.readPtr(schemaSystemAddress + profile.typeScopesPtr)

        require(scopeCount in 1..4096) {
            "invalid type-scope count $scopeCount"
        }
        require(scopesPtr != 0L) {
            "null type-scope data pointer"
        }

        val results = mutableListOf<ModuleSchemaDump>()
        var readableNames = 0

        for (index in 0 until scopeCount) {
            val scope = runCatching { mem.readPtr(scopesPtr + index * 8L) }.getOrDefault(0L)
            if (scope == 0L) continue

            val moduleName = safeString(scope + profile.scopeNameInline, profile.scopeNameMaxBytes)
            if (moduleName.isBlank()) continue
            readableNames++

            val classes = readClasses(scope, moduleName, profile)
            val enums = readEnums(scope, profile)
            if (classes.isNotEmpty() || enums.isNotEmpty()) {
                log("    [schema] $moduleName -> ${classes.size} class(es), ${enums.size} enum(s)")
                results += ModuleSchemaDump(moduleName, classes, enums)
            }
        }

        require(readableNames > 0) {
            "type-scope vector was readable but contained no valid inline scope names"
        }
        require(results.isNotEmpty()) {
            "read $readableNames named scope(s) but extracted no classes or enums"
        }

        val fieldCount = results.sumOf { scope -> scope.classes.sumOf { it.fields.size } }
        require(fieldCount > 0) {
            "extracted ${results.size} scope(s) but no reflected fields"
        }

        log(
            "  [schema] ${results.size} scope(s), " +
                "${results.sumOf { it.classes.size }} class(es), $fieldCount field(s)"
        )
        return results.sortedBy { it.moduleName }
    }

    private fun readClasses(
        scope: Long,
        moduleName: String,
        profile: SchemaLayoutProfile,
    ): List<ClassDump> {
        val pending = ArrayDeque<Long>()
        val visited = mutableSetOf<Long>()

        readHashElements(scope + profile.classesHash, profile).forEach { pointer ->
            if (pointer != 0L && visited.add(pointer)) pending.add(pointer)
        }

        val classes = mutableMapOf<Long, ClassDump>()
        while (pending.isNotEmpty()) {
            val binding = pending.removeFirst()
            val dump = runCatching {
                val name = safeString(mem.readPtr(binding + profile.bindingNamePtr))
                if (name.isBlank()) return@runCatching null

                val baseInfo = mem.readPtr(binding + profile.bindingBaseClassesPtr)
                val parent = if (baseInfo != 0L) {
                    val parentBinding = mem.readPtr(baseInfo + profile.baseClassBindingPtr)
                    if (parentBinding != 0L) {
                        if (visited.add(parentBinding)) pending.add(parentBinding)
                        safeString(mem.readPtr(parentBinding + profile.bindingNamePtr))
                            .takeIf { it.isNotBlank() }
                    } else {
                        null
                    }
                } else {
                    null
                }

                ClassDump(name, moduleName, parent, readFields(binding, profile))
            }.getOrNull() ?: continue

            classes[binding] = dump
        }
        return classes.values.sortedBy { it.name }
    }

    private fun readFields(binding: Long, profile: SchemaLayoutProfile): List<FieldDump> {
        val count = runCatching {
            mem.readI32(binding + profile.bindingFieldCount) and 0xFFFF
        }.getOrDefault(0)
        val table = runCatching {
            mem.readPtr(binding + profile.bindingFieldsPtr)
        }.getOrDefault(0L)

        if (table == 0L || count !in 1..4096) return emptyList()

        return (0 until count).mapNotNull { index ->
            runCatching {
                val entry = table + index * profile.fieldStride
                val name = safeString(mem.readPtr(entry + profile.fieldNamePtr))
                if (name.isBlank()) return@runCatching null

                val type = mem.readPtr(entry + profile.fieldTypePtr)
                    .takeIf { it != 0L }
                    ?.let { safeString(mem.readPtr(it + profile.schemaTypeNamePtr)) }
                    .orEmpty()
                    .ifBlank { "unknown" }
                val offset = mem.readI32(entry + profile.fieldOffset)

                FieldDump(name, type.replace(" ", ""), offset)
            }.getOrNull()
        }.sortedBy { it.offset }
    }

    private fun readEnums(scope: Long, profile: SchemaLayoutProfile): List<EnumDump> =
        readHashElements(scope + profile.enumsHash, profile).mapNotNull { binding ->
            runCatching {
                val name = safeString(mem.readPtr(binding + profile.enumNamePtr))
                if (name.isBlank()) return@runCatching null

                val count = mem.readI32(binding + profile.enumCount) and 0xFFFF
                val table = mem.readPtr(binding + profile.enumeratorsPtr)
                if (table == 0L || count !in 0..8192) return@runCatching EnumDump(name, emptyList())

                val members = (0 until count).mapNotNull { index ->
                    val entry = table + index * profile.enumeratorStride
                    val memberName = safeString(mem.readPtr(entry + profile.enumeratorNamePtr))
                    if (memberName.isBlank()) {
                        null
                    } else {
                        EnumMemberDump(memberName, mem.readU64(entry + profile.enumeratorValue))
                    }
                }
                EnumDump(name, members)
            }.getOrNull()
        }.sortedBy { it.name }

    private fun readHashElements(hash: Long, profile: SchemaLayoutProfile): List<Long> {
        val visitedNodes = mutableSetOf<Long>()
        val elements = mutableSetOf<Long>()

        fun follow(head: Long) {
            var node = head
            var guard = 0
            while (node != 0L && guard++ < 1_000_000 && visitedNodes.add(node)) {
                val data = runCatching { mem.readPtr(node + profile.hashNodeData) }.getOrDefault(0L)
                if (data != 0L) elements += data
                node = runCatching { mem.readPtr(node + profile.hashNodeNext) }.getOrDefault(0L)
            }
        }

        for (bucket in 0 until profile.hashBucketCount) {
            val bucketAddress = hash + profile.hashBuckets + bucket * profile.hashBucketStride
            follow(runCatching { mem.readPtr(bucketAddress + profile.hashCommittedList) }.getOrDefault(0L))
            follow(runCatching { mem.readPtr(bucketAddress + profile.hashUncommittedList) }.getOrDefault(0L))
        }

        if (elements.isNotEmpty()) return elements.toList()

        val peak = runCatching { mem.readI32(hash + profile.hashPeakAllocation) }.getOrDefault(0)
        var blob = runCatching { mem.readPtr(hash + profile.hashFreeList) }.getOrDefault(0L)
        var count = 0
        while (blob != 0L && count++ < peak.coerceIn(0, 1_000_000)) {
            val data = runCatching { mem.readPtr(blob + profile.hashNodeData) }.getOrDefault(0L)
            if (data != 0L) elements += data
            blob = runCatching { mem.readPtr(blob) }.getOrDefault(0L)
        }
        return elements.toList()
    }

    private fun safeString(address: Long, maxBytes: Int = 512): String {
        if (address == 0L) return ""
        return runCatching { mem.readString(address, maxBytes) }
            .getOrDefault("")
            .takeIf { value ->
                value.isNotBlank() && value.all { char ->
                    char == '\t' || char == '\n' || char.code in 0x20..0x7E
                }
            }
            .orEmpty()
    }
}
