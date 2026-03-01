package com.ghost.tap

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import com.ghost.tap.security.RootDetector
import com.ghost.tap.ui.theme.GhostTapTheme
import com.ghost.tap.viewmodel.WalletViewModel

class MainActivity : ComponentActivity() {

    private val walletViewModel: WalletViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Initialize Rust core
        if (!RustBridge.init()) {
            throw RuntimeException("Failed to initialize GhostTap Core")
        }

        // Load auto-lock timeout from SharedPreferences
        val prefs = getSharedPreferences("ghost_tap_prefs", MODE_PRIVATE)
        walletViewModel.autoLockMinutes = prefs.getInt("auto_lock_minutes", 5)

        setContent {
            GhostTapTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    var showRootWarning by remember { mutableStateOf(RootDetector.isRooted()) }

                    GhostTapNavigation(walletViewModel = walletViewModel)

                    if (showRootWarning) {
                        AlertDialog(
                            onDismissRequest = { showRootWarning = false },
                            title = { Text("Security Warning") },
                            text = {
                                Text(
                                    "This device appears to be rooted. " +
                                    "Your wallet keys may be at risk. " +
                                    "Proceed with caution."
                                )
                            },
                            confirmButton = {
                                TextButton(
                                    onClick = { showRootWarning = false }
                                ) {
                                    Text("I Understand")
                                }
                            }
                        )
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        walletViewModel.checkAutoLock()
    }

    override fun onPause() {
        super.onPause()
        walletViewModel.recordActivity()
    }
}
