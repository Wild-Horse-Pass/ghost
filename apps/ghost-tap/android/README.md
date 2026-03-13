# Ghost-Tap Android

Kotlin/Compose mobile wallet using `ghost-tap-core` via UniFFI/JNI bindings.

## Status: Not Production Ready

This app is **parked** pending mainnet launch. The shared Rust core library (`ghost-tap-core`) is fully functional and tested, but the Android wrapper has not been through QA or production hardening.

Do not ship this to users in its current state.

## Build

Requires Android Studio and the JNI library built from `ghost-tap-core`:

```bash
../scripts/build-android.sh
```

Then open this directory in Android Studio.
