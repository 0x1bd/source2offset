package org.kvxd.source2offset.core

data class PlatformInfo(
    val processName: String,
    val moduleKindName: String,
    val supportsElfSymbols: Boolean,
    val supportsLiveInterfaces: Boolean,
    val supportsLiveSchemas: Boolean,
    val supportsRuntimeRoots: Boolean,
    val coreSymbolModules: Set<String>,
)

expect val currentPlatform: PlatformInfo
