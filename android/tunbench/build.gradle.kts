buildscript {
    dependencies {
        // AGP's built-in Kotlin compiles with this Kotlin Gradle plugin instead of the older one
        // it depends on (https://developer.android.com/build/releases/agp-9-0-0-release-notes).
        classpath(libs.kotlin.gradle.plugin)
    }
}

plugins {
    alias(libs.plugins.android.application) apply false
}
