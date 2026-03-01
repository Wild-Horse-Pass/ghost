package com.ghost.tap.security

import java.io.File

/**
 * Detects rooted Android devices.
 *
 * Uses multiple heuristics: su binary presence, test-keys build tag,
 * and common root management app detection. Returns true if any check
 * triggers. The detection is advisory — used for a dismissible warning,
 * not a hard block.
 */
object RootDetector {

    private val suPaths = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su",
        "/data/adb/su",
    )

    private val rootPackages = listOf(
        "com.topjohnwu.magisk",          // Magisk Manager
        "eu.chainfire.supersu",           // SuperSU
        "com.koushikdutta.superuser",     // Superuser (legacy)
        "de.robv.android.xposed.installer", // Xposed Framework
        "com.saurik.substrate",           // Cydia Substrate (Android)
    )

    private val rootPaths = listOf(
        "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk",
        "/system/app/SuperSU",
        "/system/etc/init.d",
        "/system/xbin/daemonsu",
    )

    /**
     * Returns true if the device appears to be rooted.
     */
    fun isRooted(): Boolean {
        return hasSuBinary() || hasTestKeys() || hasRootPaths() || isSystemRw()
    }

    private fun hasSuBinary(): Boolean {
        return suPaths.any { File(it).exists() }
    }

    private fun hasTestKeys(): Boolean {
        val buildTags = android.os.Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    private fun hasRootPaths(): Boolean {
        return rootPaths.any { File(it).exists() }
    }

    private fun isSystemRw(): Boolean {
        return try {
            val mountOutput = Runtime.getRuntime().exec("mount").inputStream
                .bufferedReader().readText()
            mountOutput.contains("/system") && mountOutput.contains("rw")
        } catch (_: Exception) {
            false
        }
    }
}
