package com.ghost.tap.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PinSetupScreen(
    onPinSet: () -> Unit,
    onBack: () -> Unit
) {
    var pin by remember { mutableStateOf("") }
    var confirmPin by remember { mutableStateOf("") }
    var isConfirming by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Set PIN") },
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
                .padding(horizontal = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = if (isConfirming) "Confirm your PIN" else "Create a 6-digit PIN",
                style = MaterialTheme.typography.headlineSmall,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "This PIN is used as a fallback when biometrics are unavailable.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(32.dp))

            OutlinedTextField(
                value = if (isConfirming) confirmPin else pin,
                onValueChange = { value ->
                    if (value.length <= 6 && value.all { it.isDigit() }) {
                        error = null
                        if (isConfirming) confirmPin = value else pin = value
                    }
                },
                label = { Text(if (isConfirming) "Confirm PIN" else "Enter PIN") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                singleLine = true,
                isError = error != null,
                supportingText = error?.let { { Text(it) } },
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = {
                    if (!isConfirming) {
                        if (pin.length != 6) {
                            error = "PIN must be exactly 6 digits"
                        } else {
                            isConfirming = true
                            error = null
                        }
                    } else {
                        if (confirmPin != pin) {
                            error = "PINs do not match"
                            confirmPin = ""
                        } else {
                            try {
                                com.ghost.tap.RustBridge.setPin(pin)
                                onPinSet()
                            } catch (e: Exception) {
                                error = e.message ?: "Failed to set PIN"
                            }
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = if (isConfirming) confirmPin.length == 6 else pin.length == 6
            ) {
                Text(if (isConfirming) "Confirm" else "Next")
            }
        }
    }
}
