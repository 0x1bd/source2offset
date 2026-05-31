plugins {
    kotlin("multiplatform") version "2.3.20"
    kotlin("plugin.serialization") version "2.3.20"
}

group = "org.kvxd.source2offset"
version = "0.2.0"

repositories {
    mavenCentral()
}

kotlin {
    linuxX64 {
        binaries {
            executable {
                entryPoint = "org.kvxd.source2offset.cli.main"
                baseName = "source2offset"
            }
        }

        compilations.all {
            compileTaskProvider.configure {
                compilerOptions {
                    // Suppress expect/actual classes Beta warning
                    freeCompilerArgs.add("-Xexpect-actual-classes")
                }
            }
        }
    }

    sourceSets {
        commonMain.dependencies {
            implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
            implementation("com.squareup.okio:okio:3.17.0")
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}
