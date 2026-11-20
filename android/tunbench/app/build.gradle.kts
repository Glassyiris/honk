import java.util.Properties

plugins {
    id("com.android.application")
}

val ndkVer = "30.0.16248370"
val sdkDir: String = Properties().run {
    rootProject.file("local.properties").takeIf { it.exists() }?.reader()?.use { load(it) }
    getProperty("sdk.dir") ?: System.getenv("ANDROID_HOME") ?: error("set sdk.dir or ANDROID_HOME")
}

// libhonkengine.so (Rust, crates/honk-android) is built by cargo and packaged as a prebuilt jniLib.
val honkEngineDir = rootProject.file("../../crates/honk-android")
val honkJniLibs = layout.buildDirectory.dir("honk-jniLibs").get().asFile
val buildHonkEngine = tasks.register<Exec>("buildHonkEngine") {
    description = "Builds libhonkengine.so for arm64-v8a with cargo and the NDK."
    workingDir = honkEngineDir
    commandLine(
        "bash", honkEngineDir.resolve("build-android.sh").absolutePath,
        honkJniLibs.absolutePath, "$sdkDir/ndk/$ndkVer",
    )
    outputs.dir(honkJniLibs)
    // cargo tracks its own inputs (including the honk-netstack path dependency).
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
