package com.ghost.tap.ui.screens.merchant

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ghost.tap.viewmodel.MerchantViewModel

private enum class TerminalState {
    EnteringAmount,
    ShowingPaymentRequest,
    PaymentReceived
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PaymentTerminalScreen(
    merchantViewModel: MerchantViewModel,
    onBack: () -> Unit
) {
    val uiState by merchantViewModel.uiState.collectAsState()
    var amountInput by remember { mutableStateOf("0") }
    var terminalState by remember { mutableStateOf(TerminalState.EnteringAmount) }
    var lastTxId by remember { mutableStateOf("") }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Payment Terminal") },
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
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            when (terminalState) {
                TerminalState.EnteringAmount -> {
                    AmountEntrySection(
                        amountInput = amountInput,
                        onAmountChange = { newAmount -> amountInput = newAmount },
                        onCharge = {
                            val satoshis = parseAmountToSatoshis(amountInput)
                            if (satoshis > 0) {
                                merchantViewModel.preparePaymentRequest(satoshis)
                                terminalState = TerminalState.ShowingPaymentRequest
                            }
                        }
                    )
                }

                TerminalState.ShowingPaymentRequest -> {
                    PaymentRequestSection(
                        amount = parseAmountToSatoshis(amountInput),
                        address = uiState.currentReceiveAddress,
                        paymentUri = uiState.currentPaymentUri,
                        onPaymentReceived = { txId ->
                            lastTxId = txId
                            terminalState = TerminalState.PaymentReceived
                        },
                        onCancel = {
                            terminalState = TerminalState.EnteringAmount
                        }
                    )
                }

                TerminalState.PaymentReceived -> {
                    PaymentConfirmationSection(
                        amount = parseAmountToSatoshis(amountInput),
                        txId = lastTxId,
                        onWashViaWraith = {
                            merchantViewModel.queueWash(lastTxId, parseAmountToSatoshis(amountInput))
                        },
                        onNewCharge = {
                            amountInput = "0"
                            terminalState = TerminalState.EnteringAmount
                        },
                        onViewReceipt = {
                            merchantViewModel.generateReceipt(
                                lastTxId,
                                parseAmountToSatoshis(amountInput)
                            )
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun AmountEntrySection(
    amountInput: String,
    onAmountChange: (String) -> Unit,
    onCharge: () -> Unit
) {
    Spacer(modifier = Modifier.height(32.dp))

    // Amount display
    Text(
        text = formatDisplayAmount(amountInput),
        fontSize = 48.sp,
        fontWeight = FontWeight.Bold,
        color = MaterialTheme.colorScheme.primary,
        textAlign = TextAlign.Center,
        modifier = Modifier.fillMaxWidth()
    )

    Text(
        text = "GHOST",
        fontSize = 18.sp,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center,
        modifier = Modifier.fillMaxWidth()
    )

    Spacer(modifier = Modifier.height(32.dp))

    // Numeric keypad
    val keys = listOf(
        listOf("1", "2", "3"),
        listOf("4", "5", "6"),
        listOf("7", "8", "9"),
        listOf(".", "0", "<")
    )

    keys.forEach { row ->
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 4.dp),
            horizontalArrangement = Arrangement.SpaceEvenly
        ) {
            row.forEach { key ->
                KeypadButton(
                    label = key,
                    onClick = {
                        when (key) {
                            "<" -> {
                                if (amountInput.length > 1) {
                                    onAmountChange(amountInput.dropLast(1))
                                } else {
                                    onAmountChange("0")
                                }
                            }
                            "." -> {
                                if (!amountInput.contains(".")) {
                                    onAmountChange("$amountInput.")
                                }
                            }
                            else -> {
                                if (amountInput == "0") {
                                    onAmountChange(key)
                                } else {
                                    // Limit decimal places to 8
                                    val dotIndex = amountInput.indexOf('.')
                                    if (dotIndex >= 0 && amountInput.length - dotIndex > 8) {
                                        // Already at max decimals
                                    } else {
                                        onAmountChange(amountInput + key)
                                    }
                                }
                            }
                        }
                    }
                )
            }
        }
    }

    Spacer(modifier = Modifier.height(24.dp))

    // Charge button
    Button(
        onClick = onCharge,
        modifier = Modifier
            .fillMaxWidth()
            .height(56.dp),
        shape = RoundedCornerShape(16.dp),
        enabled = parseAmountToSatoshis(amountInput) > 0
    ) {
        Text(
            text = "Charge ${formatDisplayAmount(amountInput)} GHOST",
            fontSize = 18.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
private fun KeypadButton(label: String, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .size(72.dp)
            .clip(CircleShape)
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = if (label == "<") "\u232B" else label,
            fontSize = 24.sp,
            fontWeight = FontWeight.Medium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun PaymentRequestSection(
    amount: Long,
    address: String,
    paymentUri: String,
    onPaymentReceived: (String) -> Unit,
    onCancel: () -> Unit
) {
    Spacer(modifier = Modifier.height(24.dp))

    Text(
        text = "Waiting for Payment",
        style = MaterialTheme.typography.headlineSmall,
        fontWeight = FontWeight.Bold
    )

    Spacer(modifier = Modifier.height(8.dp))

    Text(
        text = formatGhostAmount(amount),
        fontSize = 36.sp,
        fontWeight = FontWeight.Bold,
        color = MaterialTheme.colorScheme.primary
    )

    Spacer(modifier = Modifier.height(24.dp))

    // QR Code placeholder (in production, render the paymentUri as a QR)
    Card(
        modifier = Modifier.size(250.dp),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color.White
        )
    ) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    text = "QR Code",
                    style = MaterialTheme.typography.titleMedium,
                    color = Color.Gray
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = address.take(20) + "...",
                    style = MaterialTheme.typography.bodySmall,
                    color = Color.Gray,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(horizontal = 16.dp)
                )
            }
        }
    }

    Spacer(modifier = Modifier.height(16.dp))

    // NFC tap indicator
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.tertiaryContainer
        ),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center
        ) {
            CircularProgressIndicator(
                modifier = Modifier.size(20.dp),
                strokeWidth = 2.dp
            )
            Spacer(modifier = Modifier.width(12.dp))
            Text(
                text = "NFC ready - tap to pay",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onTertiaryContainer
            )
        }
    }

    Spacer(modifier = Modifier.weight(1f))

    // Simulate payment received (for development)
    OutlinedButton(
        onClick = { onPaymentReceived("simulated_txid_${System.currentTimeMillis()}") },
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Text("Simulate Payment Received")
    }

    Spacer(modifier = Modifier.height(8.dp))

    TextButton(
        onClick = onCancel,
        modifier = Modifier.fillMaxWidth()
    ) {
        Text("Cancel")
    }
}

@Composable
private fun PaymentConfirmationSection(
    amount: Long,
    txId: String,
    onWashViaWraith: () -> Unit,
    onNewCharge: () -> Unit,
    onViewReceipt: () -> Unit
) {
    Spacer(modifier = Modifier.height(48.dp))

    // Success icon
    Box(
        modifier = Modifier
            .size(80.dp)
            .clip(CircleShape)
            .background(Color(0xFF4CAF50)),
        contentAlignment = Alignment.Center
    ) {
        Icon(
            Icons.Filled.Check,
            contentDescription = "Success",
            tint = Color.White,
            modifier = Modifier.size(48.dp)
        )
    }

    Spacer(modifier = Modifier.height(16.dp))

    Text(
        text = "Payment Received",
        style = MaterialTheme.typography.headlineSmall,
        fontWeight = FontWeight.Bold
    )

    Spacer(modifier = Modifier.height(8.dp))

    Text(
        text = formatGhostAmount(amount),
        fontSize = 32.sp,
        fontWeight = FontWeight.Bold,
        color = MaterialTheme.colorScheme.primary
    )

    Spacer(modifier = Modifier.height(4.dp))

    Text(
        text = "TxID: ${txId.take(16)}...",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )

    Spacer(modifier = Modifier.height(32.dp))

    // Wash via Wraith button
    OutlinedButton(
        onClick = onWashViaWraith,
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = ButtonDefaults.outlinedButtonColors(
            contentColor = MaterialTheme.colorScheme.secondary
        )
    ) {
        Text("Wash via Wraith")
    }

    Spacer(modifier = Modifier.height(8.dp))

    // View receipt
    OutlinedButton(
        onClick = onViewReceipt,
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Icon(Icons.Filled.Share, contentDescription = null, modifier = Modifier.size(18.dp))
        Spacer(modifier = Modifier.width(8.dp))
        Text("View Receipt")
    }

    Spacer(modifier = Modifier.weight(1f))

    // New charge
    Button(
        onClick = onNewCharge,
        modifier = Modifier
            .fillMaxWidth()
            .height(52.dp),
        shape = RoundedCornerShape(16.dp)
    ) {
        Text("New Charge", fontSize = 16.sp, fontWeight = FontWeight.Bold)
    }
}

private fun formatDisplayAmount(input: String): String {
    return if (input.isEmpty()) "0" else input
}

private fun parseAmountToSatoshis(input: String): Long {
    return try {
        val amount = input.toDouble()
        (amount * 100_000_000).toLong()
    } catch (e: NumberFormatException) {
        0L
    }
}

private fun formatGhostAmount(satoshis: Long): String {
    val whole = satoshis / 100_000_000
    val frac = satoshis % 100_000_000
    return "$whole.${"%08d".format(frac)} GHOST"
}
