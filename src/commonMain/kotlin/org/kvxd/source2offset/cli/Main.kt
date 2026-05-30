package org.kvxd.source2offset.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.multiple
import com.github.ajalt.clikt.parameters.options.option
import okio.FileSystem
import okio.Path.Companion.toPath
import org.kvxd.source2offset.core.MemReader
import org.kvxd.source2offset.core.Module
import org.kvxd.source2offset.core.ProcessHandle
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
expect fun currentIsoTimestamp(): String
expect fun readFileBytes(path: String): ByteArray

class Source2OffsetCmd : CliktCommand(name = "source2offset") {
    private val gameDir by option("--game-dir", help = "Optional CS2 game directory override.")
    private val outputDir by option(
        "--output-dir",
        help = "Output directory. Relative paths are resolved from the directory where the executable is run.",
    ).default("output")
    private val requestedInterfaces by option(
        "--interface",
        help = "Additional named interface to resolve as <module-keyword>:<interface-name>.",
    ).multiple()
    private val noDefaultInterfaces by option(
        "--no-default-interfaces",
        help = "Do not request built-in interface roots automatically.",
    ).flag(default = false)
    private val symbols by option(
        "--symbols",
        help = "Write diagnostic symbols.kt/json for retained ELF names in core modules. Disabled by default.",
    ).flag(default = false)
    private val allSymbols by option(
        "--all-symbols",
        help = "Write diagnostic symbols.kt/json for every bundled CS2 .so. Implies --symbols.",
    ).flag(default = false)
    private val metadataOnly by option(
        "--metadata-only",
        help = "Disable validated private/global dw* analysis; emit only interfaces, schemas and RTTI roots.",
    ).flag(default = false)
    private val requireSchema by option(
        "--require-schema",
        help = "Mark the run as unsuccessful unless reflected schema fields were dumped successfully. Diagnostic output files are still written.",
    ).flag(default = false)

    override fun run() {
        println("source2offset — native Linux Source 2 metadata and validated offset dumper")
        println()

        val pid = findProcessPid("cs2") ?: run {
            println("ERROR: no native CS2 process was found.")
            return
        }
        println("Process: pid=$pid")

        val mappings = runCatching { parseMemoryMap(pid) }.getOrElse { error ->
            println("ERROR: unable to read /proc/$pid/maps: ${error.message}")
            return
        }
        val modules = parseModuleMap(pid)
        val (detectedGameDir, gameModules) = modules.filterGameModules(gameDir)
        if (gameModules.isEmpty()) {
            println("ERROR: no native CS2 ELF modules found in the process mappings.")
            println("Game directory candidate: ${detectedGameDir ?: gameDir ?: "none"}")
            return
        }
        println("Game directory: $detectedGameDir")
        println("Native ELF modules: ${gameModules.size}")
        gameModules.sortedBy { it.name }.forEach {
            println("  ${it.name.padEnd(30)} ${it.base.hexAddress()}")
        }
        println()

        val requests = buildRequests()
        println("Resolving named interfaces through live CreateInterface calls...")
        val interfaces = LiveInterfaceResolver(gameModules, ::readFileBytes)
            .resolve(pid, requests) { println(it) }
        println("Resolved interfaces: ${interfaces.size}/${requests.size}")
        println()

        val handle = runCatching { ProcessHandle(pid) }.getOrElse { error ->
            println("ERROR: failed to open non-stopping live memory reader: ${error.message}")
            return
        }

        val exportSymbols = symbols || allSymbols
        val modulesForSymbols = when {
            allSymbols -> gameModules
            symbols -> coreSymbolModules(gameModules)
            else -> emptyList()
        }
        if (symbols && !allSymbols) {
            println(
                "Diagnostic symbol export restricted to core modules: " +
                        modulesForSymbols.joinToString { it.name } +
                        " (use --all-symbols for all ${gameModules.size} bundled modules)"
            )
        } else if (!exportSymbols) {
            println("Diagnostic ELF symbol export disabled (pass --symbols only when investigating retained names).")
        }
        if (metadataOnly) {
            println("Private/global dw* analysis disabled by --metadata-only.")
        } else {
            println("Validated private/global dw* analysis enabled.")
        }

        val result = try {
            DumpEngine(
                mem = MemReader(handle),
                gameModules = gameModules,
                modulesForSymbols = modulesForSymbols,
                includeSymbols = exportSymbols,
                includePrivateOffsets = !metadataOnly,
                mappings = mappings,
                resolvedInterfaces = interfaces,
                readFile = ::readFileBytes,
                timestamp = currentIsoTimestamp(),
                log = { println(it) },
            ).run()
        } finally {
            handle.close()
        }

        writeOutputs(result)
        printSummary(result)

        if (requireSchema && result.schemas.isEmpty()) {
            println()
            println("ERROR: --require-schema was specified, but no live schema output was produced.")
            println("Diagnostic interfaces, offsets, runtime roots and report files were still written.")
        }
    }

    private fun writeOutputs(result: DumpResult) {
        val out = outputDir.toPath()
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
        println("Dump complete: ${result.timestamp}")
        println("  Interfaces : ${result.interfaces.values.sumOf { it.size }}")
        println("  Offsets    : ${result.offsets.values.sumOf { it.size }} validated entry/entries")
        println("  Schemas    : ${result.schemas.size} scope(s), ${result.schemas.sumOf { it.classes.size }} class(es)")
        println("  Fields     : ${result.schemas.sumOf { scope -> scope.classes.sumOf { it.fields.size } }}")
        println("  RTTI roots : ${result.runtimeRoots.size}")
        println("  Symbols    : ${if (result.symbols.isEmpty()) "not written" else "${result.symbols.values.sumOf { it.size }} diagnostic entries"}")
        println("  Output     : $outputDir (relative to your current working directory)")
        println()
        result.capabilities.forEach { println("[${it.level}] ${it.feature}: ${it.message}") }
    }

    private fun buildRequests(): List<InterfaceRequest> {
        val defaults = if (noDefaultInterfaces) emptyList() else listOf(
            InterfaceRequest("schemasystem", "SchemaSystem_001"),
            InterfaceRequest("engine2", "GameResourceServiceClientV001"),
            InterfaceRequest("client", "Source2ClientPrediction001"),
            InterfaceRequest("inputsystem", "InputSystemVersion001"),
            InterfaceRequest("soundsystem", "SoundSystem001"),
        )
        val extras = requestedInterfaces.mapNotNull { spec ->
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
        val core = setOf("libclient.so", "libengine2.so", "libschemasystem.so")
        return modules.filter { it.name in core }
    }
}

fun main(args: Array<String>) = Source2OffsetCmd().main(args)
