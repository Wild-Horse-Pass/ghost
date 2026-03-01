package com.ghost.tap.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    autoLockMinutes: Int = 5,
    onAutoLockChanged: (Int) -> Unit = {}
) {
    var networkEndpoint by remember { mutableStateOf("https://ghost-rpc.example.com") }
    var biometricEnabled by remember { mutableStateOf(true) }
    var wraithMode by remember { mutableStateOf(false) }
    var merchantMode by remember { mutableStateOf(false) }
    var showEndpointDialog by remember { mutableStateOf(false) }
    var showAutoLockDialog by remember { mutableStateOf(false) }
    var selectedAutoLock by remember { mutableIntStateOf(autoLockMinutes) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
        ) {
            // Network section
            SettingsSectionHeader("Network")

            ListItem(
                headlineContent = { Text("RPC Endpoint") },
                supportingContent = { Text(networkEndpoint) },
                leadingContent = {
                    Icon(Icons.Default.Cloud, contentDescription = null)
                },
                trailingContent = {
                    IconButton(onClick = { showEndpointDialog = true }) {
                        Icon(Icons.Default.Edit, contentDescription = "Edit")
                    }
                }
            )

            HorizontalDivider(modifier = Modifier.padding(horizontal = 16.dp))

            // Security section
            SettingsSectionHeader("Security")

            ListItem(
                headlineContent = { Text("Biometric Authentication") },
                supportingContent = { Text("Require biometrics to confirm transactions") },
                leadingContent = {
                    Icon(Icons.Default.Fingerprint, contentDescription = null)
                },
                trailingContent = {
                    Switch(
                        checked = biometricEnabled,
                        onCheckedChange = { biometricEnabled = it }
                    )
                }
            )

            ListItem(
                headlineContent = { Text("Auto-Lock Timeout") },
                supportingContent = { Text("$selectedAutoLock minute${if (selectedAutoLock != 1) "s" else ""}") },
                leadingContent = {
                    Icon(Icons.Default.Timer, contentDescription = null)
                },
                trailingContent = {
                    IconButton(onClick = { showAutoLockDialog = true }) {
                        Icon(Icons.Default.Edit, contentDescription = "Edit")
                    }
                }
            )

            HorizontalDivider(modifier = Modifier.padding(horizontal = 16.dp))

            // Privacy section
            SettingsSectionHeader("Privacy")

            ListItem(
                headlineContent = { Text("Wraith Mode") },
                supportingContent = {
                    Text(
                        if (wraithMode) "Transactions use private ledger"
                        else "Transactions use public ledger"
                    )
                },
                leadingContent = {
                    Icon(
                        if (wraithMode) Icons.Default.VisibilityOff
                        else Icons.Default.Visibility,
                        contentDescription = null
                    )
                },
                trailingContent = {
                    Switch(
                        checked = wraithMode,
                        onCheckedChange = { wraithMode = it }
                    )
                }
            )

            HorizontalDivider(modifier = Modifier.padding(horizontal = 16.dp))

            // Merchant section
            SettingsSectionHeader("Merchant")

            ListItem(
                headlineContent = { Text("Merchant Mode") },
                supportingContent = {
                    Text(
                        if (merchantMode) "Accepting payments as merchant"
                        else "Consumer wallet mode"
                    )
                },
                leadingContent = {
                    Icon(Icons.Default.Storefront, contentDescription = null)
                },
                trailingContent = {
                    Switch(
                        checked = merchantMode,
                        onCheckedChange = { merchantMode = it }
                    )
                }
            )

            HorizontalDivider(modifier = Modifier.padding(horizontal = 16.dp))

            // About section
            SettingsSectionHeader("About")

            ListItem(
                headlineContent = { Text("App Version") },
                supportingContent = { Text("GhostTap v0.1.0") },
                leadingContent = {
                    Icon(Icons.Default.Info, contentDescription = null)
                }
            )

            ListItem(
                headlineContent = { Text("Core Library") },
                supportingContent = {
                    Text(
                        try {
                            "ghost-tap-core ${com.ghost.tap.RustBridge.version()}"
                        } catch (_: Exception) {
                            "ghost-tap-core (unavailable)"
                        }
                    )
                },
                leadingContent = {
                    Icon(Icons.Default.Memory, contentDescription = null)
                }
            )

            Spacer(modifier = Modifier.height(32.dp))
        }
    }

    // Auto-lock timeout picker dialog
    if (showAutoLockDialog) {
        val options = listOf(1, 5, 15, 30, 60)
        AlertDialog(
            onDismissRequest = { showAutoLockDialog = false },
            title = { Text("Auto-Lock Timeout") },
            text = {
                Column {
                    options.forEach { minutes ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = selectedAutoLock == minutes,
                                onClick = { selectedAutoLock = minutes }
                            )
                            Text(
                                text = "$minutes minute${if (minutes != 1) "s" else ""}",
                                modifier = Modifier.padding(start = 8.dp)
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    onAutoLockChanged(selectedAutoLock)
                    showAutoLockDialog = false
                }) {
                    Text("Save")
                }
            },
            dismissButton = {
                TextButton(onClick = { showAutoLockDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    // Endpoint edit dialog
    if (showEndpointDialog) {
        var editedEndpoint by remember { mutableStateOf(networkEndpoint) }

        AlertDialog(
            onDismissRequest = { showEndpointDialog = false },
            title = { Text("RPC Endpoint") },
            text = {
                OutlinedTextField(
                    value = editedEndpoint,
                    onValueChange = { editedEndpoint = it },
                    label = { Text("URL") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        networkEndpoint = editedEndpoint
                        showEndpointDialog = false
                    }
                ) {
                    Text("Save")
                }
            },
            dismissButton = {
                TextButton(onClick = { showEndpointDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}

@Composable
private fun SettingsSectionHeader(title: String) {
    Text(
        text = title,
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 16.dp, top = 24.dp, bottom = 8.dp)
    )
}
