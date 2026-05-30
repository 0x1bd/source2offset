package org.kvxd.source2offset.schema

data class FieldDump(
    val name: String,
    val typeName: String,
    val offset: Int,
)

data class ClassDump(
    val name: String,
    val moduleName: String,
    val parentName: String?,
    val fields: List<FieldDump>,
)

data class EnumMemberDump(
    val name: String,
    val value: Long,
)

data class EnumDump(
    val name: String,
    val members: List<EnumMemberDump>,
)

data class ModuleSchemaDump(
    val moduleName: String,
    val classes: List<ClassDump>,
    val enums: List<EnumDump>,
)

data class SchemaLayoutProfile(
    val name: String,
    val typeScopesCount: Long,
    val typeScopesPtr: Long,
    val scopeNameInline: Long,
    val scopeNameMaxBytes: Int,
    val classesHash: Long,
    val enumsHash: Long,
    val bindingNamePtr: Long,
    val bindingFieldCount: Long,
    val bindingFieldsPtr: Long,
    val bindingBaseClassesPtr: Long,
    val fieldNamePtr: Long,
    val fieldTypePtr: Long,
    val fieldOffset: Long,
    val fieldStride: Long,
    val schemaTypeNamePtr: Long,
    val baseClassBindingPtr: Long,
    val enumNamePtr: Long,
    val enumeratorsPtr: Long,
    val enumCount: Long,
    val enumeratorNamePtr: Long,
    val enumeratorValue: Long,
    val enumeratorStride: Long,
    val hashPeakAllocation: Long,
    val hashFreeList: Long,
    val hashBuckets: Long,
    val hashBucketCount: Int,
    val hashBucketStride: Long,
    val hashCommittedList: Long,
    val hashUncommittedList: Long,
    val hashNodeNext: Long,
    val hashNodeData: Long,
)

val SOURCE2_DOCUMENTED_CURRENT_SCHEMA_PROFILE = SchemaLayoutProfile(
    name = "source2-documented-current",
    typeScopesCount = 0x190L,
    typeScopesPtr = 0x198L,
    scopeNameInline = 0x008L,
    scopeNameMaxBytes = 256,
    classesHash = 0x560L,
    enumsHash = 0x1DD0L,
    bindingNamePtr = 0x008L,
    bindingFieldCount = 0x024L,
    bindingFieldsPtr = 0x030L,
    bindingBaseClassesPtr = 0x040L,
    fieldNamePtr = 0x000L,
    fieldTypePtr = 0x008L,
    fieldOffset = 0x010L,
    fieldStride = 0x020L,
    schemaTypeNamePtr = 0x008L,
    baseClassBindingPtr = 0x018L,
    enumNamePtr = 0x008L,
    enumeratorsPtr = 0x020L,
    enumCount = 0x01CL,
    enumeratorNamePtr = 0x000L,
    enumeratorValue = 0x008L,
    enumeratorStride = 0x020L,
    hashPeakAllocation = 0x010L,
    hashFreeList = 0x020L,
    hashBuckets = 0x060L,
    hashBucketCount = 256,
    hashBucketStride = 0x018L,
    hashCommittedList = 0x008L,
    hashUncommittedList = 0x010L,
    hashNodeNext = 0x008L,
    hashNodeData = 0x010L,
)

val SOURCE2_NATIVE_LINUX_OBSERVED_SCHEMA_PROFILE = SchemaLayoutProfile(
    name = "source2-native-linux-observed",
    typeScopesCount = 0x1F0L,
    typeScopesPtr = 0x1F8L,
    scopeNameInline = 0x008L,
    scopeNameMaxBytes = 256,
    classesHash = 0x560L,
    enumsHash = 0x3600L,
    bindingNamePtr = 0x008L,
    bindingFieldCount = 0x024L,
    bindingFieldsPtr = 0x030L,
    bindingBaseClassesPtr = 0x038L,
    fieldNamePtr = 0x000L,
    fieldTypePtr = 0x008L,
    fieldOffset = 0x010L,
    fieldStride = 0x020L,
    schemaTypeNamePtr = 0x008L,
    baseClassBindingPtr = 0x008L,
    enumNamePtr = 0x008L,
    enumeratorsPtr = 0x020L,
    enumCount = 0x01CL,
    enumeratorNamePtr = 0x000L,
    enumeratorValue = 0x008L,
    enumeratorStride = 0x020L,
    hashPeakAllocation = 0x014L,
    hashFreeList = 0x020L,
    hashBuckets = 0x090L,
    hashBucketCount = 256,
    hashBucketStride = 0x030L,
    hashCommittedList = 0x020L,
    hashUncommittedList = 0x028L,
    hashNodeNext = 0x008L,
    hashNodeData = 0x010L,
)

val SUPPORTED_SCHEMA_PROFILES: List<SchemaLayoutProfile> = listOf(
    SOURCE2_DOCUMENTED_CURRENT_SCHEMA_PROFILE,
    SOURCE2_NATIVE_LINUX_OBSERVED_SCHEMA_PROFILE,
)
