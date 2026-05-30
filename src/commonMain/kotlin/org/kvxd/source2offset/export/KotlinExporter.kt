package org.kvxd.source2offset.export

import org.kvxd.source2offset.schema.ClassDump
import org.kvxd.source2offset.schema.FieldDump
import org.kvxd.source2offset.schema.ModuleSchemaDump

object KotlinExporter {
    private const val PKG = "org.kvxd.source2offset.offsets"

    fun buildInterfacesKt(result: DumpResult): String = buildString {
        header("interfaces.kt")
        appendLine("package $PKG")
        appendLine()

        val moduleNames = NameAllocator()
        for ((module, entries) in result.interfaces.entries.sortedBy { it.key }) {
            val objectName = moduleNames.allocate("${module}_Interfaces")
            val entryNames = NameAllocator()
            appendLine("object $objectName {")
            for (entry in entries.sortedBy { it.name }) {
                val name = entryNames.allocate(entry.name)
                appendLine("    const val $name: Long = 0x${entry.rva.toULong().toString(16).uppercase()}L")
            }
            appendLine("}")
            appendLine()
        }
    }

    fun buildOffsetsKt(result: DumpResult): String = buildString {
        header("offsets.kt")
        appendLine("package $PKG")
        appendLine()
        appendLine("import org.kvxd.unsafeKt.UnsafeKt")
        appendLine()
        appendLine("object Offsets {")
        val moduleNames = NameAllocator()
        for ((module, entries) in result.offsets.entries.sortedBy { it.key }) {
            val moduleObject = moduleNames.allocate(module.replaceFirstChar { it.uppercase() })
            val names = NameAllocator()
            appendLine("    object $moduleObject {")
            for (entry in entries.sortedBy { it.name }) {
                val name = names.allocate(entry.name)
                val suffix = name.replaceFirstChar { it.uppercase() }
                appendLine("        const val $name: Long = 0x${entry.rva.toULong().toString(16).uppercase()}L")
                when (entry.access) {
                    "pointer_slot_rva" -> {
                        appendLine("        fun ${name}SlotAddress(moduleBase: Long): Long = moduleBase + $name")
                        appendLine("        fun resolve$suffix(moduleBase: Long, mem: UnsafeKt): Long = mem.readLong(${name}SlotAddress(moduleBase))")
                    }

                    "direct_address_rva" -> {
                        appendLine("        fun ${name}Address(moduleBase: Long): Long = moduleBase + $name")
                    }

                    "member_offset" -> {
                        appendLine("        fun ${name}Address(objectAddress: Long): Long = objectAddress + $name")
                    }
                }
                appendLine()
            }
            appendLine("    }")
            appendLine()
        }
        appendLine("}")
    }

    fun buildSymbolsKt(result: DumpResult): String = buildString {
        header("symbols.kt")
        appendLine("package $PKG")
        appendLine()

        val moduleNames = NameAllocator()
        for ((module, symbols) in result.symbols.entries.sortedBy { it.key }) {
            val visible = symbols
                .filter { it.binding != "local" && (it.kind == "function" || it.kind == "object") }
                .sortedBy { it.name }
            if (visible.isEmpty()) continue

            val objectName = moduleNames.allocate("${module.replaceFirstChar { it.uppercase() }}Symbols")
            val symbolNames = NameAllocator()
            appendLine("object $objectName {")
            for (symbol in visible) {
                val name = symbolNames.allocate(symbol.name)
                appendLine(
                    "    const val $name: Long = 0x${symbol.rva.toULong().toString(16).uppercase()}L " +
                            "// ${escapeComment(symbol.kind)}, ${escapeComment(symbol.table)}, original=${
                                escapeComment(
                                    symbol.name
                                )
                            }"
                )
            }
            appendLine("}")
            appendLine()
        }
    }

    fun buildRuntimeRootsKt(result: DumpResult): String = buildString {
        header("runtime_roots.kt")
        appendLine("package $PKG")
        appendLine()
        appendLine("import org.kvxd.unsafeKt.UnsafeKt")
        appendLine()
        appendLine("object RuntimeRoots {")

        if (result.runtimeRoots.isEmpty()) {
            appendLine("    // No consumer-useful RTTI-verifiable roots were discovered in this dump.")
        } else {
            val rootNames = NameAllocator()
            for (root in result.runtimeRoots.sortedBy { it.name }) {
                val objectName = rootNames.allocate(root.name.replaceFirstChar { it.uppercase() })
                appendLine("    object $objectName {")
                appendLine("        const val SOURCE_MODULE: String = \"${escapeString(root.sourceModule)}\"")
                appendLine("        const val SOURCE_INTERFACE: String = \"${escapeString(root.sourceInterface)}\"")
                appendLine(
                    "        const val SOURCE_INTERFACE_RVA: Long = 0x${
                        root.sourceInterfaceRva.toULong().toString(16).uppercase()
                    }L"
                )
                appendLine(
                    "        const val MEMBER_OFFSET: Long = 0x${
                        root.memberOffset.toULong().toString(16).uppercase()
                    }L"
                )
                appendLine("        const val VERIFIED_TARGET_TYPE: String = \"${escapeString(root.targetType)}\"")
                appendLine()
                appendLine("        /** Resolve the live target through the RTTI-verified interface relationship. */")
                appendLine("        fun resolve(sourceModuleBase: Long, mem: UnsafeKt): Long =")
                appendLine("            mem.readLong(sourceModuleBase + SOURCE_INTERFACE_RVA + MEMBER_OFFSET)")
                appendLine("    }")
                appendLine()
            }
        }

        appendLine("}")
    }

    fun buildSchemaKtMap(result: DumpResult): Map<String, String> {
        val names = GeneratedSchemaNames(result.schemas)
        return result.schemas.associate { scope ->
            val key = normaliseModuleName(scope.moduleName)
            key to buildSchemaKt(key, scope, names)
        }
    }

    private fun buildSchemaKt(
        key: String,
        scope: ModuleSchemaDump,
        names: GeneratedSchemaNames,
    ): String = buildString {
        header("$key.kt")
        appendLine("package $PKG")
        appendLine()
        appendLine("import org.kvxd.unsafeKt.UnsafeKt")
        appendLine("import org.kvxd.unsafeKt.mem.Struct")
        appendLine()

        val objectName = names.objectNameForScope(scope)
        appendLine("object $objectName {")
        appendLine()

        for (klass in scope.classes.sortedBy { it.name }) {
            appendSchemaClass(scope, klass, names.classId(scope, klass), names)
        }

        if (scope.enums.isNotEmpty()) {
            appendLine("    object Enums {")
            val orderedEnums = scope.enums.sortedBy { it.name }
            val enumIds = allocateInOrder(orderedEnums.map { it.name })
            for ((enum, enumName) in orderedEnums.zip(enumIds)) {
                appendLine("        object $enumName {")
                appendLine("            const val SCHEMA_NAME: String = \"${escapeString(enum.name)}\"")
                val orderedMembers = enum.members.sortedBy { it.name }
                val memberIds = allocateInOrder(orderedMembers.map { it.name }, setOf("SCHEMA_NAME"))
                for ((member, memberId) in orderedMembers.zip(memberIds)) {
                    appendLine("            const val $memberId: Long = ${member.value}L")
                }
                appendLine("        }")
                appendLine()
            }
            appendLine("    }")
        }
        appendLine("}")
    }

    private fun StringBuilder.appendSchemaClass(
        scope: ModuleSchemaDump,
        klass: ClassDump,
        classId: String,
        names: GeneratedSchemaNames,
    ) {
        val reserved = setOf("SCHEMA_NAME", "PARENT_SCHEMA_NAME")
        val orderedFields = klass.fields.sortedBy { it.offset }
        val fieldIds = allocateInOrder(orderedFields.map { it.name }, reserved)
        val fields = orderedFields.zip(fieldIds)

        appendLine(
            "    /** Fields declared directly by ${escapeKDoc(klass.name)}." +
                    (klass.parentName?.let { " Reflected parent: ${escapeKDoc(it)}." } ?: "") + " */")
        appendLine("    object $classId {")
        appendLine("        const val SCHEMA_NAME: String = \"${escapeString(klass.name)}\"")
        klass.parentName?.let {
            appendLine("        const val PARENT_SCHEMA_NAME: String = \"${escapeString(it)}\"")
        }
        for ((field, fieldId) in fields) {
            appendLine(
                "        const val $fieldId: Long = " +
                        "0x${
                            field.offset.toUInt().toString(16).uppercase()
                        }L // ${escapeComment(field.typeName)}; schema=${escapeComment(field.name)}"
            )
        }
        appendLine("    }")
        appendLine()

        appendLine("    class ${classId}Struct(base: Long, mem: UnsafeKt) : Struct(base, mem) {")
        if (klass.fields.isEmpty()) {
            appendLine("        // No directly declared reflected fields.")
        }
        val propertyNames = NameAllocator()
        for ((field, fieldId) in fields) {
            appendMappedField(scope, classId, field, fieldId, names, propertyNames)
        }
        appendLine("    }")
        appendLine()
    }

    private fun StringBuilder.appendMappedField(
        scope: ModuleSchemaDump,
        classId: String,
        field: FieldDump,
        fieldId: String,
        names: GeneratedSchemaNames,
        propertyNames: NameAllocator,
    ) {
        val mapping = mapPrimitiveOrPointerType(field.typeName)
        if (mapping != null) {
            val property = propertyNames.allocate(fieldId)
            appendLine("        var $property: ${mapping.kotlinType} by ${mapping.delegate}($classId.$fieldId)")
            return
        }

        val embedded = names.embeddedTarget(scope, field.typeName)
        if (embedded != null) {
            val property = propertyNames.allocate(fieldId)
            appendLine("        /** Embedded reflected value: ${escapeKDoc(field.typeName)}. */")
            appendLine("        val $property: ${embedded.ownerObject}.${embedded.classId}Struct")
            appendLine("            get() = ${embedded.ownerObject}.${embedded.classId}Struct(base + $classId.$fieldId, mem)")
            return
        }

        val property = propertyNames.allocate("${fieldId}Address")
        appendLine("        /** Raw address of ${escapeKDoc(field.name)}: ${escapeKDoc(field.typeName)}; no safe value decoder was proven. */")
        appendLine("        val $property: Long get() = base + $classId.$fieldId")
    }

    private data class TypeMapping(val delegate: String, val kotlinType: String)

    private fun mapPrimitiveOrPointerType(type: String): TypeMapping? = when {
        '[' in type -> null
        type == "bool" -> TypeMapping("bool", "Boolean")
        type in setOf("int8", "char") -> TypeMapping("int8", "Byte")
        type == "uint8" -> TypeMapping("uint8", "UByte")
        type == "int16" -> TypeMapping("int16", "Short")
        type == "uint16" -> TypeMapping("uint16", "UShort")
        type in setOf("int32", "int", "Color") -> TypeMapping("int32", "Int")
        type in setOf("uint32", "uint") -> TypeMapping("uint32", "UInt")
        type in setOf("int64", "long") -> TypeMapping("int64", "Long")
        type in setOf("uint64", "ulong") -> TypeMapping("uint64", "ULong")
        type in setOf("float32", "float") -> TypeMapping("float", "Float")
        type in setOf("float64", "double") -> TypeMapping("double", "Double")
        '*' in type || type == "CUtlString" || type == "CUtlSymbolLarge" -> TypeMapping("ptr64", "Long")
        type.startsWith("CHandle<") -> TypeMapping("uint32", "UInt")
        else -> null
    }

    private class GeneratedSchemaNames(scopes: List<ModuleSchemaDump>) {
        data class Target(val scope: ModuleSchemaDump, val ownerObject: String, val classId: String)

        private val scopeObjectNames: Map<ModuleSchemaDump, String>
        private val classIds: Map<Pair<ModuleSchemaDump, ClassDump>, String>
        private val classesBySchemaName: Map<String, List<Target>>

        init {
            val scopeAllocator = NameAllocator()
            scopeObjectNames = scopes.sortedBy { it.moduleName }.associateWith { scope ->
                scopeAllocator.allocate(normaliseModuleName(scope.moduleName).replaceFirstChar { it.uppercase() } + "Schema")
            }

            val ids = mutableMapOf<Pair<ModuleSchemaDump, ClassDump>, String>()
            val targets = mutableMapOf<String, MutableList<Target>>()
            for (scope in scopes) {
                val classAllocator = NameAllocator()
                for (klass in scope.classes.sortedBy { it.name }) {
                    val id = classAllocator.allocate(klass.name)
                    ids[scope to klass] = id
                    targets.getOrPut(klass.name) { mutableListOf() }
                        .add(Target(scope, scopeObjectNames.getValue(scope), id))
                }
            }
            classIds = ids
            classesBySchemaName = targets
        }

        fun objectNameForScope(scope: ModuleSchemaDump): String = scopeObjectNames.getValue(scope)

        fun classId(scope: ModuleSchemaDump, klass: ClassDump): String = classIds.getValue(scope to klass)

        fun embeddedTarget(currentScope: ModuleSchemaDump, typeName: String): Target? {
            if ('*' in typeName || '<' in typeName || '[' in typeName) return null
            val matches = classesBySchemaName[typeName.trim()] ?: return null
            return matches.singleOrNull { it.scope == currentScope } ?: matches.singleOrNull()
        }
    }

    private fun allocateInOrder(rawNames: List<String>, reserved: Set<String> = emptySet()): List<String> {
        val allocator = NameAllocator(reserved)
        return rawNames.map { allocator.allocate(it) }
    }

    private class NameAllocator(reserved: Set<String> = emptySet()) {
        private val used = reserved.toMutableSet()

        fun allocate(raw: String): String {
            val base = kotlinIdentifier(raw)
            var candidate = base
            var suffix = 2
            while (!used.add(candidate)) {
                candidate = "${base}_$suffix"
                suffix++
            }
            return candidate
        }
    }

    private fun StringBuilder.header(filename: String) {
        appendLine("// ============================================================")
        appendLine("// $filename")
        appendLine("// Auto-generated by source2offset; do not edit manually")
        appendLine("// ============================================================")
        appendLine()
    }

    private fun kotlinIdentifier(value: String): String {
        val stripped = value.replace(Regex("[^A-Za-z0-9_]"), "_").ifEmpty { "Unknown" }
        val prefixed = if (stripped.first().isDigit()) "_$stripped" else stripped
        return if (prefixed in KOTLIN_KEYWORDS) "${prefixed}_" else prefixed
    }

    private fun escapeString(value: String): String = value
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")

    private fun escapeKDoc(value: String): String = value.replace("*/", "* /")

    private fun escapeComment(value: String): String = value
        .replace("\n", " ")
        .replace("\r", " ")

    private val KOTLIN_KEYWORDS = setOf(
        "as", "break", "class", "continue", "do", "else", "false", "for", "fun", "if",
        "in", "interface", "is", "null", "object", "package", "return", "super", "this",
        "throw", "true", "try", "typealias", "typeof", "val", "var", "when", "while",
        "by", "catch", "constructor", "delegate", "dynamic", "field", "file", "finally",
        "get", "import", "init", "param", "property", "receiver", "set", "setparam",
        "where", "actual", "abstract", "annotation", "companion", "const", "crossinline",
        "data", "enum", "expect", "external", "final", "infix", "inline", "inner",
        "internal", "lateinit", "noinline", "open", "operator", "out", "override",
        "private", "protected", "public", "reified", "sealed", "suspend", "tailrec",
        "vararg",
    )
}