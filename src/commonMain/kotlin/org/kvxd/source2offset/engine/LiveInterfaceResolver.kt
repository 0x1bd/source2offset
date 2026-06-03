package org.kvxd.source2offset.engine

import org.kvxd.source2offset.core.Module
import org.kvxd.source2offset.export.InterfaceEntry

data class InterfaceRequest(
    val moduleKeyword: String,
    val interfaceName: String,
)

data class RemoteInterfaceCall(
    val moduleName: String,
    val moduleBase: Long,
    val interfaceName: String,
    val createInterfaceAddress: Long,
)

data class RemoteInterfaceResult(
    val call: RemoteInterfaceCall,
    val instanceAddress: Long?,
    val error: String? = null,
)

expect fun callCreateInterfaces(pid: Int, calls: List<RemoteInterfaceCall>): List<RemoteInterfaceResult>

expect class LiveInterfaceResolver(
    modules: List<Module>,
    readFile: (String) -> ByteArray,
) {
    fun resolve(pid: Int, requests: List<InterfaceRequest>, log: (String) -> Unit = {}): List<InterfaceEntry>
}
