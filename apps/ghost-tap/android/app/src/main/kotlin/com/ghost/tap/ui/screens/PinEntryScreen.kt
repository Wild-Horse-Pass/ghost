package com.ghost.tap.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

@Composable
fun PinEntryScreen(
    onUnlocked: () -> Unit,
    remainingAttempts: Int
) {
    var pin by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var attempts by remember { mutableIntStateOf(remainingAttempts) }
    var isLockedOut by remember { mutableStateOf(remainingAttempts == 0) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = "Enter PIN",
            style = MaterialTheme.typography.headlineMedium,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(8.dp))

        if (isLockedOut) {
            Text(
                text = "Too many failed attempts. Please re-import your wallet using your mnemonic phrase.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
                textAlign = TextAlign.Center
            )
        } else {
            Text(
                text = "$attempts attempts remaining",
                style = MaterialTheme.typography.bodyMedium,
                color = if (attempts <= 2) MaterialTheme.colorScheme.error
                       else MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )
        }

        Spacer(modifier = Modifier.height(32.dp))

        OutlinedTextField(
            value = pin,
            onValueChange = { value ->
                if (value.length <= 6 && value.all { it.isDigit() }) {
                    pin = value
                    error = null
                }
            },
            label = { Text("PIN") },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
            singleLine = true,
            isError = error != null,
            supportingText = error?.let { { Text(it) } },
            enabled = !isLockedOut,
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(24.dp))

        Button(
            onClick = {
                val result = com.ghost.tap.RustBridge.verifyPinAndUnlock(pin)
                when (result) {
                    0 -> onUnlocked()
                    1 -> {
                        attempts--
                        error = "Wrong PIN"
                        pin = ""
                    }
                    2 -> {
                        isLockedOut = true
                        error = "Account locked"
                    }
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = pin.length == 6 && !isLockedOut
        ) {
            Text("Unlock")
        }

        Spacer(modifier = Modifier.height(16.dp))

        TextButton(
            onClick = {
                val success = com.ghost.tap.RustBridge.authenticateBiometric()
                if (success) onUnlocked()
            },
            enabled = !isLockedOut
        ) {
            Text("Use Biometrics")
        }
    }
}
