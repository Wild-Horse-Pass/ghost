package com.ghost.tap.ui.screens.merchant

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ghost.tap.viewmodel.MerchantViewModel
import com.ghost.tap.viewmodel.WashStatus as VmWashStatus

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MerchantDashboardScreen(
    merchantViewModel: MerchantViewModel,
    onNavigateToTerminal: () -> Unit,
    onNavigateToProfile: () -> Unit,
    onNavigateToExport: () -> Unit,
    onNavigateToInvoice: () -> Unit,
    onNavigateToSettings: () -> Unit,
    onTransactionClick: (String) -> Unit,
    onBack: () -> Unit
) {
    val uiState by merchantViewModel.uiState.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Merchant Dashboard") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = onNavigateToSettings) {
                        Icon(Icons.Filled.Settings, contentDescription = "Settings")
                    }
                }
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Sales summary cards
            item {
                Text(
                    text = "Sales Overview",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 8.dp)
                )
            }

            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    SalesSummaryCard(
                        label = "Today",
                        amount = uiState.dailyTotal,
                        count = uiState.dailyCount,
                        modifier = Modifier.weight(1f)
                    )
                    SalesSummaryCard(
                        label = "This Week",
                        amount = uiState.weeklyTotal,
                        count = uiState.weeklyCount,
                        modifier = Modifier.weight(1f)
                    )
                    SalesSummaryCard(
                        label = "This Month",
                        amount = uiState.monthlyTotal,
                        count = uiState.monthlyCount,
                        modifier = Modifier.weight(1f)
                    )
                }
            }

            // Wraith wash status
            item {
                WraithWashStatusCard(
                    queuedCount = uiState.washQueuedCount,
                    inProgressCount = uiState.washInProgressCount,
                    completedCount = uiState.washCompletedCount,
                    failedCount = uiState.washFailedCount
                )
            }

            // Quick action buttons
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Button(
                        onClick = onNavigateToTerminal,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text("Charge")
                    }
                    OutlinedButton(
                        onClick = onNavigateToInvoice,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text("Invoice")
                    }
                    OutlinedButton(
                        onClick = onNavigateToExport,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text("Export")
                    }
                }
            }

            // Recent transactions
            item {
                Text(
                    text = "Recent Transactions",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }

            if (uiState.recentTransactions.isEmpty()) {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant
                        )
                    ) {
                        Text(
                            text = "No transactions yet. Use the terminal to start accepting payments.",
                            modifier = Modifier.padding(24.dp),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            } else {
                items(uiState.recentTransactions) { tx ->
                    MerchantTransactionRow(
                        txId = tx.txId,
                        amount = tx.amount,
                        timestamp = tx.timestamp,
                        status = tx.status,
                        washStatus = tx.washStatus,
                        onClick = { onTransactionClick(tx.txId) }
                    )
                }
            }

            item { Spacer(modifier = Modifier.height(24.dp)) }
        }
    }
}

@Composable
private fun SalesSummaryCard(
    label: String,
    amount: Long,
    count: Int,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer
        ),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onPrimaryContainer
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = formatGhost(amount),
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = "$count txns",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
            )
        }
    }
}

@Composable
private fun WraithWashStatusCard(
    queuedCount: Int,
    inProgressCount: Int,
    completedCount: Int,
    failedCount: Int
) {
    val total = queuedCount + inProgressCount + completedCount + failedCount
    if (total == 0) return

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer
        ),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "Wraith Wash Status",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSecondaryContainer
            )
            Spacer(modifier = Modifier.height(8.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                WashStatusPill("Queued", queuedCount, Color(0xFF9E9E9E))
                WashStatusPill("Active", inProgressCount, Color(0xFF2196F3))
                WashStatusPill("Done", completedCount, Color(0xFF4CAF50))
                if (failedCount > 0) {
                    WashStatusPill("Failed", failedCount, Color(0xFFF44336))
                }
            }
        }
    }
}

@Composable
private fun WashStatusPill(label: String, count: Int, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Box(
            modifier = Modifier
                .background(color.copy(alpha = 0.15f), RoundedCornerShape(8.dp))
                .padding(horizontal = 12.dp, vertical = 4.dp)
        ) {
            Text(
                text = count.toString(),
                fontWeight = FontWeight.Bold,
                fontSize = 16.sp,
                color = color
            )
        }
        Spacer(modifier = Modifier.height(2.dp))
        Text(text = label, style = MaterialTheme.typography.labelSmall)
    }
}

@Composable
private fun MerchantTransactionRow(
    txId: String,
    amount: Long,
    timestamp: Long,
    status: String,
    washStatus: VmWashStatus?,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(8.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = txId.take(12) + "...",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = formatTimestamp(timestamp),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (washStatus != null) {
                    Text(
                        text = "Wash: ${washStatus.label}",
                        style = MaterialTheme.typography.labelSmall,
                        color = when (washStatus) {
                            VmWashStatus.Queued -> Color(0xFF9E9E9E)
                            VmWashStatus.InProgress -> Color(0xFF2196F3)
                            VmWashStatus.Completed -> Color(0xFF4CAF50)
                            VmWashStatus.Failed -> Color(0xFFF44336)
                        }
                    )
                }
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    text = "+${formatGhost(amount)}",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF4CAF50)
                )
                Text(
                    text = status,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

private fun formatGhost(satoshis: Long): String {
    val whole = satoshis / 100_000_000
    val frac = satoshis % 100_000_000
    return "$whole.${"%08d".format(frac)} GHOST"
}

private fun formatTimestamp(timestamp: Long): String {
    val date = java.util.Date(timestamp * 1000)
    val format = java.text.SimpleDateFormat("MMM dd, HH:mm", java.util.Locale.getDefault())
    return format.format(date)
}
