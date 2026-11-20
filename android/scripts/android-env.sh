# Source this (bash or zsh) before building honk-netstack or crates/honk-android for Android.
# Override before sourcing: JAVA_HOME (a JDK 21; kept if already set), ANDROID_HOME (default
# $HOME/Android/Sdk, Android Studio's location), NDK_VERSION (default 30.0.16248370, the version
# the TunBench Gradle build pins), NDK_HOST_TAG (default linux-x86_64).
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/${NDK_VERSION:-30.0.16248370}"
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin${JAVA_HOME:+:$JAVA_HOME/bin}:$PATH"
_ndk_bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/${NDK_HOST_TAG:-linux-x86_64}/bin"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$_ndk_bin/aarch64-linux-android29-clang"
export CC_aarch64_linux_android="$_ndk_bin/aarch64-linux-android29-clang"
export CXX_aarch64_linux_android="$_ndk_bin/aarch64-linux-android29-clang++"
export AR_aarch64_linux_android="$_ndk_bin/llvm-ar"
unset _ndk_bin
