plugins {
    id("com.android.application")
}

val ndkVer = "30.0.16248370"

// libhonkengine.so (Rust, crates/honk-android) is built by cargo-ndk and packaged as a prebuilt jniLib.
val honkEngineDir = rootProject.file("../../crates/honk-android")
val honkJniLibs = layout.buildDirectory.dir("honk-jniLibs").get().asFile
val cargoBin = (System.getenv("CARGO_HOME") ?: "${System.getProperty("user.home")}/.cargo") + "/bin"
// rustup's default location when present, so a Gradle daemon started without cargo on PATH works.
val cargo = File(cargoBin, "cargo").takeIf { it.canExecute() }?.path ?: "cargo"
val ndkDir = androidComponents.sdkComponents.ndkDirectory
val buildHonkEngine = tasks.register<Exec>("buildHonkEngine") {
    description = "Builds libhonkengine.so for arm64-v8a with cargo-ndk and the NDK."
    workingDir = honkEngineDir // rustup reads rust-toolchain.toml from the working directory
    commandLine(
        cargo, "ndk", "-t", "arm64-v8a", "--platform", "29",
        "-o", honkJniLibs.absolutePath, "build", "--release", "--locked",
    )
    environment("PATH", cargoBin + File.pathSeparator + System.getenv("PATH"))
    doFirst { environment("ANDROID_NDK_HOME", ndkDir.get().asFile.absolutePath) }
    outputs.dir(honkJniLibs)
    // Always runs: Cargo decides what to rebuild (it tracks the honk-netstack path dependency).
    outputs.upToDateWhen { false }
}
tasks.named("preBuild") { dependsOn(buildHonkEngine) }

android {
    namespace = "dev.tunbench"
    compileSdk = 37
    ndkVersion = ndkVer

    defaultConfig {
        applicationId = "dev.tunbench"
        minSdk = 29
        targetSdk = 37
        versionCode = 1
        versionName = "1.0"

        ndk {
            abiFilters += "arm64-v8a"
        }

        externalNativeBuild {
            ndkBuild {
                // Build only the JNI library, not hev's standalone executable.
                targets += "hev-socks5-tunnel"
                // Optimized native code even in the debug APK: this is a benchmark.
                arguments += listOf(
                    "NDK_DEBUG=0",
                    "NDK_APPLICATION_MK=" + file("src/main/jni/Application.mk").absolutePath,
                )
            }
        }
    }

    externalNativeBuild {
        ndkBuild {
            path = file("src/main/jni/Android.mk")
        }
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDir(honkJniLibs)
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
