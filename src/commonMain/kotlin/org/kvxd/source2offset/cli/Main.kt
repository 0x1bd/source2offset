package org.kvxd.source2offset.cli

import okio.FileSystem
import okio.Path.Companion.toPath
import org.kvxd.source2offset.core.MemReader
import org.kvxd.source2offset.core.Module
import org.kvxd.source2offset.core.ProcessHandle
import org.kvxd.source2offset.core.currentPlatform
import org.kvxd.source2offset.core.filterGameModules
import org.kvxd.source2offset.core.hexAddress
import org.kvxd.source2offset.core.parseMemoryMap
import org.kvxd.source2offset.core.parseModuleMap
import org.kvxd.source2offset.engine.DumpEngine
import org.kvxd.source2offset.engine.InterfaceRequest
import org.kvxd.source2offset.engine.LiveInterfaceResolver
import org.kvxd.source2offset.export.DumpResult
import org.kvxd.source2offset.export.JsonExporter
import org.kvxd.source2offset.export.KotlinExporter

expect fun findProcessPid(name: String): Int?
expect fun processHasLaunchArgument(pid: Int, argument: String): Boolean?
expect fun readFileBytes(path: String): ByteArray

private data class CliOptions(
    val gameDir: String? = null,
    val outputDir: String = "output",
    val requestedInterfaces: List<String> = emptyList(),
    val noDefaultInterfaces: Boolean = false,
    val symbols: Boolean = false,
    val allSymbols: Boolean = false,
    val metadataOnly: Boolean = false,
    val requireSchema: Boolean = false,
)

private class Source2OffsetCmd(private val options: CliOptions) {
    constructor(args: Array<String>) : this(parseArgs(args))

    companion object {
        private fun parseArgs(args: Array<String>): CliOptions {
            var gameDir: String? = null
            var outputDir = "output"
            val requestedInterfaces = mutableListOf<String>()
            var noDefaultInterfaces = false
            var symbols = false
            var allSymbols = false
            var metadataOnly = false
            var requireSchema = false

            fun valueAt(index: Int, option: String): String {
                require(index + 1 < args.size) { "Missing value for $option" }
                return args[index + 1]
            }

            var i = 0
            while (i < args.size) {
                val arg = args[i]
                val split = arg.indexOf('=')
                val name = if (split >= 0) arg.substring(0, split) else arg
                val inlineValue = if (split >= 0) arg.substring(split + 1) else null

                when (name) {
                    "--game-dir" -> {
                        gameDir = inlineValue ?: valueAt(i, name)
                        if (inlineValue == null) i++
                    }

                    "--output-dir" -> {
                        outputDir = inlineValue ?: valueAt(i, name)
                        if (inlineValue == null) i++
                    }

                    "--interface" -> {
                        requestedInterfaces += inlineValue ?: valueAt(i, name)
                        if (inlineValue == null) i++
                    }

                    "--no-default-interfaces" -> noDefaultInterfaces = true
                    "--symbols" -> symbols = true
                    "--all-symbols" -> allSymbols = true
                    "--metadata-only" -> metadataOnly = true
                    "--require-schema" -> requireSchema = true
                    "--help", "-h" -> {
                        printUsage()
                        throw ExitRequested
                    }

                    else -> error("Unknown argument: $arg")
                }
                i++
            }

            return CliOptions(
                gameDir = gameDir,
                outputDir = outputDir,
                requestedInterfaces = requestedInterfaces,
                noDefaultInterfaces = noDefaultInterfaces,
                symbols = symbols,
                allSymbols = allSymbols,
                metadataOnly = metadataOnly,
                requireSchema = requireSchema,
            )
        }

        private fun printUsage() {
            println(
                """
                Usage: source2offset [options]

                Options:
                  --game-dir <path>             Optional CS2 game directory override.
                  --output-dir <path>           Output directory. Defaults to output.
                  --interface <module:name>     Additional named interface to resolve.
                  --no-default-interfaces       Do not request built-in interface roots.
                  --symbols                     Write symbols.kt/json for core modules.
                  --all-symbols                 Write symbols.kt/json for every CS2 module.
                  --metadata-only               Emit only interfaces, schemas and RTTI roots.
                  --require-schema              Print an error if no schema fields were dumped.
                  --help                        Show this help.
                """.trimIndent()
            )
        }
    }

    fun run() {
        println("source2offset")
        println()

        val pid = findProcessPid(currentPlatform.processName) ?: run {
            println("ERROR: no native CS2 process was found.")
            return
        }
        println("Process: pid=$pid")

        when (processHasLaunchArgument(pid, "-insecure")) {
            true -> Unit
            false -> {
                println("ERROR: CS2 must be launched with -insecure before source2offset can run.")
                println("Add -insecure to CS2 launch options, restart the game, then run source2offset again.")
                return
            }
            null -> {
                println("ERROR: unable to verify that CS2 was launched with -insecure.")
                println("source2offset will not run unless -insecure can be confirmed in the CS2 command line.")
                return
            }
        }

        val mappings = runCatching { parseMemoryMap(pid) }.getOrElse { error ->
            println("ERROR: unable to read process module map for pid=$pid: ${error.message}")
            return
        }
        val modules = parseModuleMap(pid)
        val (detectedGameDir, gameModules) = modules.filterGameModules(options.gameDir)
        if (gameModules.isEmpty()) {
            println("ERROR: no native CS2 ${currentPlatform.moduleKindName} modules found in the process mappings.")
            println("Game directory candidate: ${detectedGameDir ?: options.gameDir ?: "none"}")
            return
        }
        println("Game directory: $detectedGameDir")
        println("Native ${currentPlatform.moduleKindName} modules: ${gameModules.size}")
        gameModules.sortedBy { it.name }.forEach {
            println("  ${it.name.padEnd(30)} ${it.base.hexAddress()}")
        }
        println()

        val requests = buildRequests()
        val interfaces = if (currentPlatform.supportsLiveInterfaces) {
            println("Resolving named interfaces through live CreateInterface calls...")
            LiveInterfaceResolver(gameModules, ::readFileBytes)
                .resolve(pid, requests, ::printIssue)
        } else {
            println("Live CreateInterface resolution is not available on this platform.")
            emptyList()
        }
        if (currentPlatform.supportsLiveInterfaces) {
            println("Resolved interfaces: ${interfaces.size}/${requests.size}")
        }
        println()

        val handle = runCatching { ProcessHandle(pid) }.getOrElse { error ->
            println("ERROR: failed to open non-stopping live memory reader: ${error.message}")
            return
        }

        val exportSymbols = options.symbols || options.allSymbols
        val modulesForSymbols = when {
            options.allSymbols -> gameModules
            options.symbols -> coreSymbolModules(gameModules)
            else -> emptyList()
        }
        if (options.symbols && !options.allSymbols) {
            println("Symbols: ${modulesForSymbols.joinToString { it.name }}")
        }

        val result = try {
            DumpEngine(
                mem = MemReader(handle),
                gameModules = gameModules,
                modulesForSymbols = modulesForSymbols,
                includeSymbols = exportSymbols,
                includePrivateOffsets = !options.metadataOnly,
                mappings = mappings,
                resolvedInterfaces = interfaces,
                readFile = ::readFileBytes,
                log = ::printIssue,
                progress = { println(it) },
            ).run()
        } finally {
            handle.close()
        }

        writeOutputs(result)
        printSummary(result)

        if (options.requireSchema && result.schemas.isEmpty()) {
            println()
            println("ERROR: --require-schema was specified, but no live schema output was produced.")
            println("Diagnostic interfaces, offsets, runtime roots and report files were still written.")
        }
    }

    private fun writeOutputs(result: DumpResult) {
        val out = options.outputDir.toPath()
        FileSystem.SYSTEM.createDirectories(out)
        FileSystem.SYSTEM.write(out.resolve("interfaces.json")) { writeUtf8(JsonExporter.buildInterfacesJson(result)) }
        FileSystem.SYSTEM.write(out.resolve("offsets.json")) { writeUtf8(JsonExporter.buildOffsetsJson(result)) }
        FileSystem.SYSTEM.write(out.resolve("runtime_roots.json")) { writeUtf8(JsonExporter.buildRuntimeRootsJson(result)) }
        FileSystem.SYSTEM.write(out.resolve("report.json")) { writeUtf8(JsonExporter.buildReportJson(result)) }
        FileSystem.SYSTEM.write(out.resolve("interfaces.kt")) { writeUtf8(KotlinExporter.buildInterfacesKt(result)) }
        FileSystem.SYSTEM.write(out.resolve("offsets.kt")) { writeUtf8(KotlinExporter.buildOffsetsKt(result)) }
        FileSystem.SYSTEM.write(out.resolve("runtime_roots.kt")) { writeUtf8(KotlinExporter.buildRuntimeRootsKt(result)) }
        if (result.symbols.isNotEmpty()) {
            FileSystem.SYSTEM.write(out.resolve("symbols.json")) { writeUtf8(JsonExporter.buildSymbolsJson(result)) }
            FileSystem.SYSTEM.write(out.resolve("symbols.kt")) { writeUtf8(KotlinExporter.buildSymbolsKt(result)) }
        }
        for ((name, content) in JsonExporter.buildSchemaJsonMap(result)) {
            FileSystem.SYSTEM.write(out.resolve("$name.json")) { writeUtf8(content) }
        }
        for ((name, content) in KotlinExporter.buildSchemaKtMap(result)) {
            FileSystem.SYSTEM.write(out.resolve("$name.kt")) { writeUtf8(content) }
        }
    }

    private fun printSummary(result: DumpResult) {
        println()
        println("Dump complete.")
        println("  Interfaces : ${result.interfaces.values.sumOf { it.size }}")
        println("  Offsets    : ${result.offsets.values.sumOf { it.size }}")
        println("  Schemas    : ${result.schemas.size} scope(s), ${result.schemas.sumOf { it.classes.size }} class(es)")
        println("  Fields     : ${result.schemas.sumOf { scope -> scope.classes.sumOf { it.fields.size } }}")
        println("  RTTI roots : ${result.runtimeRoots.size}")
        println("  Symbols    : ${if (result.symbols.isEmpty()) "not written" else "${result.symbols.values.sumOf { it.size }} diagnostic entries"}")
        println("  Output     : ${options.outputDir} (relative to your current working directory)")
    }

    private fun buildRequests(): List<InterfaceRequest> {
        val defaults = if (options.noDefaultInterfaces) emptyList() else listOf(
            InterfaceRequest("schemasystem", "SchemaSystem_001"),
            InterfaceRequest("engine2", "GameResourceServiceClientV001"),
            InterfaceRequest("client", "Source2ClientPrediction001"),
            InterfaceRequest("inputsystem", "InputSystemVersion001"),
            InterfaceRequest("soundsystem", "SoundSystem001"),
        )
        val extras = options.requestedInterfaces.mapNotNull { spec ->
            val separator = spec.indexOf(':')
            if (separator <= 0 || separator == spec.lastIndex) {
                println("WARN: ignoring malformed --interface '$spec'; expected <module-keyword>:<interface-name>")
                null
            } else {
                InterfaceRequest(spec.substring(0, separator), spec.substring(separator + 1))
            }
        }
        return (defaults + extras).distinct()
    }

    private fun coreSymbolModules(modules: List<Module>): List<Module> {
        return modules.filter { it.name in currentPlatform.coreSymbolModules }
    }

    private fun printIssue(message: String) {
        if (message.startsWith("WARN:") || message.startsWith("ERROR:")) {
            println(message)
        }
    }
}

private object ExitRequested : RuntimeException()

fun main(args: Array<String>) {
    try {
        Source2OffsetCmd(args).run()
    } catch (_: ExitRequested) {
    } catch (error: IllegalArgumentException) {
        println("ERROR: ${error.message}")
    } catch (error: IllegalStateException) {
        println("ERROR: ${error.message}")
    }
}
