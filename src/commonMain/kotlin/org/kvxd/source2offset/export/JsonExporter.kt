package org.kvxd.source2offset.export

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

object JsonExporter {
    private val json = Json { prettyPrint = true; prettyPrintIndent = "  " }

    fun buildInterfacesJson(result: DumpResult): String = json.encodeToString(
        buildJsonObject {
            for ((module, entries) in result.interfaces.entries.sortedBy { it.key }) {
                putJsonObject(module) {
                    for (entry in entries.sortedBy { it.name }) {
                        putJsonObject(entry.name) {
                            put("rva", entry.rva)
                            put("addressAtDumpTime", entry.address)
                            put("semantics", "direct_interface_instance_rva")
                            put("provenance", "live_CreateInterface_call")
                        }
                    }
                }
            }
        }
    )

    fun buildOffsetsJson(result: DumpResult): String = json.encodeToString(
        buildJsonObject {
            for ((module, entries) in result.offsets.entries.sortedBy { it.key }) {
                putJsonObject(module) {
                    for (entry in entries.sortedBy { it.name }) {
                        putJsonObject(entry.name) {
                            put("rva", entry.rva)
                            put("access", entry.access)
                            put("discovery", entry.discovery)
                            put("validation", entry.validation)
                            put("confidence", entry.confidence)
                            if (entry.note.isNotBlank()) put("note", entry.note)
                        }
                    }
                }
            }
        }
    )

    fun buildSymbolsJson(result: DumpResult): String = json.encodeToString(
        buildJsonObject {
            for ((module, entries) in result.symbols.entries.sortedBy { it.key }) {
                putJsonArray(module) {
                    for (entry in entries.sortedBy { it.name }) {
                        addJsonObject {
                            put("name", entry.name)
                            put("rva", entry.rva)
                            put("size", entry.size)
                            put("kind", entry.kind)
                            put("binding", entry.binding)
                            put("table", entry.table)
                            put("provenance", "retained_ELF_symbol_name")
                        }
                    }
                }
            }
        }
    )

    fun buildRuntimeRootsJson(result: DumpResult): String = json.encodeToString(
        buildJsonObject {
            putJsonArray("roots") {
                for (root in result.runtimeRoots.sortedBy { it.name }) {
                    addJsonObject {
                        put("name", root.name)
                        put("sourceModule", root.sourceModule)
                        put("sourceInterface", root.sourceInterface)
                        put("sourceInterfaceRva", root.sourceInterfaceRva)
                        put("memberOffset", root.memberOffset)
                        put("verifiedTargetType", root.targetType)
                        put("targetAddressAtDumpTime", root.targetAddress)
                        put("provenance", "live_itanium_RTTI_verified_relationship")
                    }
                }
            }
        }
    )

    fun buildReportJson(result: DumpResult): String = json.encodeToString(
        buildJsonObject {
            put("timestamp", result.timestamp)
            putJsonArray("capabilities") {
                for (item in result.capabilities) {
                    addJsonObject {
                        put("level", item.level)
                        put("feature", item.feature)
                        put("message", item.message)
                    }
                }
            }
            put("schemaScopes", result.schemas.size)
            put("schemaClasses", result.schemas.sumOf { it.classes.size })
            put("schemaFields", result.schemas.sumOf { scope -> scope.classes.sumOf { it.fields.size } })
            put("namedInterfaces", result.interfaces.values.sumOf { it.size })
            put("rttiRuntimeRoots", result.runtimeRoots.size)
            put("validatedOffsets", result.offsets.values.sumOf { it.size })
        }
    )

    fun buildSchemaJsonMap(result: DumpResult): Map<String, String> = result.schemas.associate { scope ->
        val key = normaliseModuleName(scope.moduleName)
        key to json.encodeToString(
            buildJsonObject {
                putJsonObject(key) {
                    put("offsetSemantics", "declared_fields_relative_to_class_object")
                    put("wrapperInheritanceGenerated", false)
                    putJsonObject("classes") {
                        for (klass in scope.classes.sortedBy { it.name }) {
                            putJsonObject(klass.name) {
                                klass.parentName?.let { put("reflectedParent", it) }
                                put("fieldsAreDeclaredDirectlyOnThisClass", true)
                                putJsonObject("fields") {
                                    for (field in klass.fields.sortedBy { it.offset }) {
                                        putJsonObject(field.name) {
                                            put("offset", field.offset)
                                            put("type", field.typeName)
                                        }
                                    }
                                }
                            }
                        }
                    }
                    putJsonObject("enums") {
                        for (enum in scope.enums.sortedBy { it.name }) {
                            putJsonObject(enum.name) {
                                for (member in enum.members.sortedBy { it.name }) put(member.name, member.value)
                            }
                        }
                    }
                }
            }
        )
    }
}
