package com.ghost.tap.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.ghost.tap.viewmodel.SyncStatus
import com.ghost.tap.viewmodel.Transaction
import com.ghost.tap.viewmodel.TxStatus
import com.ghost.tap.viewmodel.WalletViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    walletViewModel: WalletViewModel,
    onSend: () -> Unit,
    onReceive: () -> Unit,
    onScan: () -> Unit,
    onTransactionClick: (String) -> Unit,
    onSettings: () -> Unit
) {
    val uiState by walletViewModel.uiState.collectAsState()
    val isRefreshing = uiState.syncStatus == SyncStatus.Syncing

    // Initial refresh
    LaunchedEffect(Unit) {
        walletViewModel.refreshBalance()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Wallet") },
                actions = {
                    if (uiState.syncStatus == SyncStatus.Syncing) {
                        CircularProgressIndicator(
                            modifier = Modifier
                                .size(20.dp)
                                .padding(end = 4.dp),
                            strokeWidth = 2.dp
                        )
                    }
                    IconButton(onClick = onSettings) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                }
            )
        }
    ) { paddingValues ->
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = { walletViewModel.refreshBalance() },
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
        ) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // Balance card
                item {
                    BalanceCard(balance = uiState.balance)
                }

                // Quick actions
                item {
                    QuickActionsRow(
                        onSend = onSend,
                        onReceive = onReceive,
                        onScan = onScan
                    )
                }

                // Transactions header
                item {
                    Text(
                        text = "Recent Transactions",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                }

                if (uiState.transactions.isEmpty()) {
                    item {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 48.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Icon(
                                    imageVector = Icons.Default.Receipt,
                                    contentDescription = null,
                                    modifier = Modifier.size(48.dp),
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                                )
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(
                                    text = "No transactions yet",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                } else {
                    items(
                        items = uiState.transactions,
                        key = { it.txId }
                    ) { tx ->
                        TransactionRow(
                            transaction = tx,
                            onClick = { onTransactionClick(tx.txId) }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun BalanceCard(balance: Long) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(20.dp)
        ) {
            Text(
                text = "Balance",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "${formatBalance(balance)} GHOST",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onPrimaryContainer
            )
        }
    }
}

@Composable
private fun QuickActionsRow(
    onSend: () -> Unit,
    onReceive: () -> Unit,
    onScan: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceEvenly
    ) {
        QuickActionButton(
            icon = Icons.Default.ArrowUpward,
            label = "Send",
            onClick = onSend
        )
        QuickActionButton(
            icon = Icons.Default.ArrowDownward,
            label = "Receive",
            onClick = onReceive
        )
        QuickActionButton(
            icon = Icons.Default.QrCodeScanner,
            label = "Scan",
            onClick = onScan
        )
    }
}

@Composable
private fun QuickActionButton(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    onClick: () -> Unit
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        FilledTonalIconButton(
            onClick = onClick,
            modifier = Modifier.size(56.dp)
        ) {
            Icon(icon, contentDescription = label)
        }
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall
        )
    }
}

@Composable
private fun TransactionRow(
    transaction: Transaction,
    onClick: () -> Unit
) {
    val dismissState = rememberSwipeToDismissBoxState(
        confirmValueChange = { false } // Prevent actual dismiss, just visual
    )

    SwipeToDismissBox(
        state = dismissState,
        backgroundContent = {
            val color by animateColorAsState(
                targetValue = MaterialTheme.colorScheme.surfaceVariant,
                label = "swipeBg"
            )
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(color)
                    .padding(horizontal = 20.dp),
                contentAlignment = Alignment.CenterEnd
            ) {
                Icon(
                    Icons.Default.Info,
                    contentDescription = "Details",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        content = {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(onClick = onClick)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Direction icon
                    FilledTonalIconButton(
                        onClick = {},
                        modifier = Modifier.size(40.dp),
                        enabled = false,
                        colors = IconButtonDefaults.filledTonalIconButtonColors(
                            disabledContainerColor = if (transaction.isSend)
                                MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.5f)
                            else
                                MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.5f)
                        )
                    ) {
                        Icon(
                            imageVector = if (transaction.isSend)
                                Icons.Default.ArrowUpward
                            else
                                Icons.Default.ArrowDownward,
                            contentDescription = if (transaction.isSend) "Sent" else "Received",
                            tint = if (transaction.isSend)
                                MaterialTheme.colorScheme.error
                            else
                                MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(20.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(12.dp))

                    // Address and timestamp
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = truncateAddress(transaction.address),
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = relativeTimestamp(transaction.timestamp),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }

                    // Amount and status
                    Column(horizontalAlignment = Alignment.End) {
                        Text(
                            text = "${if (transaction.isSend) "-" else "+"}${formatBalance(transaction.amount)}",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = if (transaction.isSend)
                                MaterialTheme.colorScheme.error
                            else
                                MaterialTheme.colorScheme.primary
                        )
                        StatusBadge(status = transaction.status)
                    }
                }
            }
        }
    )
}

@Composable
fun StatusBadge(status: TxStatus) {
    val (text, color) = when (status) {
        TxStatus.Confirmed -> "Confirmed" to MaterialTheme.colorScheme.primary
        TxStatus.Pending -> "Pending" to MaterialTheme.colorScheme.tertiary
        TxStatus.Failed -> "Failed" to MaterialTheme.colorScheme.error
    }
    Text(
        text = text,
        style = MaterialTheme.typography.labelSmall,
        color = color
    )
}

private fun truncateAddress(address: String): String {
    if (address.length <= 16) return address
    return "${address.take(8)}...${address.takeLast(8)}"
}

private fun formatBalance(amount: Long): String {
    val decimal = amount.toDouble() / 100_000_000.0
    return String.format("%.8f", decimal)
}

private fun relativeTimestamp(epochSeconds: Long): String {
    if (epochSeconds == 0L) return "Pending"
    val now = System.currentTimeMillis() / 1000
    val diff = now - epochSeconds
    return when {
        diff < 60 -> "Just now"
        diff < 3600 -> "${diff / 60}m ago"
        diff < 86400 -> "${diff / 3600}h ago"
        diff < 604800 -> "${diff / 86400}d ago"
        else -> {
            val sdf = java.text.SimpleDateFormat("MMM d, yyyy", java.util.Locale.US)
            sdf.format(java.util.Date(epochSeconds * 1000))
        }
    }
}
