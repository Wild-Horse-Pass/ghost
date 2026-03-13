# Ghost-Tap iOS

Swift/SwiftUI mobile wallet using `ghost-tap-core` via UniFFI bindings.

## Status: Not Production Ready

This app is **parked** pending mainnet launch. The shared Rust core library (`ghost-tap-core`) is fully functional and tested, but the iOS wrapper has not been through QA or production hardening.

Do not ship this to users in its current state.

## Build

Requires Xcode 15+ and the iOS XCFramework built from `ghost-tap-core`:

```bash
../scripts/build-ios.sh
```

Then open `GhostTap.xcodeproj` in Xcode.
