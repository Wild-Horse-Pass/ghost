import Foundation

/// Detects jailbroken iOS devices using multiple heuristics.
///
/// The detection is advisory — used for a dismissible warning, not a hard block.
enum JailbreakDetector {

    private static let suspiciousPaths = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/usr/sbin/sshd",
        "/etc/apt",
        "/usr/bin/ssh",
        "/private/var/lib/apt/",
        "/var/lib/cydia",
        "/var/cache/apt",
        "/var/lib/dpkg",
        "/usr/libexec/cydia",
        "/usr/lib/libhooker.dylib",
    ]

    /// Returns true if the device appears to be jailbroken.
    static func isJailbroken() -> Bool {
        return hasSuspiciousPaths()
            || canWriteOutsideSandbox()
            || canFork()
            || hasInjectedDylibs()
    }

    private static func hasSuspiciousPaths() -> Bool {
        return suspiciousPaths.contains { FileManager.default.fileExists(atPath: $0) }
    }

    private static func canWriteOutsideSandbox() -> Bool {
        let testPath = "/private/jailbreak_test_\(UUID().uuidString)"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {
            return false
        }
    }

    private static func canFork() -> Bool {
        let pid = fork()
        if pid >= 0 {
            // fork succeeded — this shouldn't happen on non-jailbroken devices
            if pid > 0 {
                // parent: kill child
                kill(pid, SIGTERM)
            }
            return true
        }
        return false
    }

    private static func hasInjectedDylibs() -> Bool {
        let suspiciousLibs = [
            "MobileSubstrate",
            "libhooker",
            "SubstrateLoader",
            "TweakInject",
        ]

        let count = _dyld_image_count()
        for i in 0..<count {
            guard let name = _dyld_get_image_name(i) else { continue }
            let imageName = String(cString: name)
            if suspiciousLibs.contains(where: { imageName.contains($0) }) {
                return true
            }
        }
        return false
    }
}
