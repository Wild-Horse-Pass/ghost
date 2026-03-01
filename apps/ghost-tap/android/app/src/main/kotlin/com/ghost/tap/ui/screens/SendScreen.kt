package com.ghost.tap.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Send
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.ghost.tap.viewmodel.SendResult
import com.ghost.tap.viewmodel.WalletViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SendScreen(
    walletViewModel: WalletViewModel,
    onBack: () -> Unit,
    onSent: () -> Unit
) {
    val uiState by walletViewModel.uiState.collectAsState()
    val focusManager = LocalFocusManager.current

    var address by remember { mutableStateOf("") }
    var amountText by remember { mutableStateOf("") }
    var feePriority by remember { mutableIntStateOf(1) } // 0=Low, 1=Medium, 2=High
    var showReview by remember { mutableStateOf(false) }

    val amount = remember(amountText) {
        try {
            (amountText.toDouble() * 100_000_000).toLong()
        } catch (_: NumberFormatException) {
            0L
        }
    }

    val canSend = address.isNotBlank() && amount > 0

    // Handle send result
    LaunchedEffect(uiState.sendResult) {
        when (uiState.sendResult) {
            is SendResult.Success -> {
                walletViewModel.clearSendResult()
                onSent()
            }
            else -> {}
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Send") },
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
                .padding(horizontal = 24.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Spacer(modifier = Modifier.height(16.dp))

            // Available balance
            Text(
                text = "Available: ${formatSendBalance(uiState.balance)} GHOST",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Address input
            OutlinedTextField(
                value = address,
                onValueChange = { address = it.trim() },
                label = { Text("Recipient Address") },
                placeholder = { Text("Enter Ghost address") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                keyboardOptions = KeyboardOptions(
                    imeAction = ImeAction.Next
                )
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Amount input
            OutlinedTextField(
                value = amountText,
                onValueChange = { newVal ->
                    // Allow only valid decimal input
                    if (newVal.isEmpty() || newVal.matches(Regex("^\\d*\\.?\\d{0,8}$"))) {
                        amountText = newVal
                    }
                },
                label = { Text("Amount (GHOST)") },
                placeholder = { Text("0.00000000") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Decimal,
                    imeAction = ImeAction.Done
                ),
                keyboardActions = KeyboardActions(
                    onDone = { focusManager.clearFocus() }
                )
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Fee selector
            Text(
                text = "Network Fee",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold
            )

            Spacer(modifier = Modifier.height(8.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                listOf("Low" to 0, "Medium" to 1, "High" to 2).forEach { (label, priority) ->
                    FilterChip(
                        selected = feePriority == priority,
                        onClick = { feePriority = priority },
                        label = { Text(label) },
                        modifier = Modifier.weight(1f)
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = when (feePriority) {
                    0 -> "Lower fee, slower confirmation (~30 min)"
                    1 -> "Standard fee, normal confirmation (~10 min)"
                    else -> "Higher fee, faster confirmation (~2 min)"
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Review summary (shown when inputs are valid)
            if (canSend) {
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "Transaction Summary",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold
                        )
                        Spacer(modifier = Modifier.height(12.dp))
                        SummaryRow("To", truncateForReview(address))
                        SummaryRow("Amount", "$amountText GHOST")
                        SummaryRow("Fee", when (feePriority) {
                            0 -> "Low"
                            1 -> "Medium"
                            else -> "High"
                        })
                    }
                }
            }

            // Error display
            if (uiState.sendResult is SendResult.Error) {
                Spacer(modifier = Modifier.height(16.dp))
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer
                    )
                ) {
                    Text(
                        text = (uiState.sendResult as SendResult.Error).message,
                        modifier = Modifier.padding(16.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer
                    )
                }
            }

            Spacer(modifier = Modifier.weight(1f))

            // Send button with biometric icon
            Button(
                onClick = {
                    focusManager.clearFocus()
                    walletViewModel.sendPayment(address, amount, feePriority)
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 24.dp),
                enabled = canSend && !uiState.isSending
            ) {
                if (uiState.isSending) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Sending...")
                } else {
                    Icon(
                        Icons.Default.Fingerprint,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Confirm & Send")
                }
            }
        }
    }
}

@Composable
private fun SummaryRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Medium
        )
    }
}

private fun formatSendBalance(amount: Long): String {
    val decimal = amount.toDouble() / 100_000_000.0
    return String.format("%.8f", decimal)
}

private fun truncateForReview(address: String): String {
    if (address.length <= 20) return address
    return "${address.take(10)}...${address.takeLast(10)}"
}
