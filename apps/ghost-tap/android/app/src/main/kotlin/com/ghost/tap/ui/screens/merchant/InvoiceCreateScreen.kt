package com.ghost.tap.ui.screens.merchant

import android.app.DatePickerDialog
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.ghost.tap.viewmodel.MerchantViewModel
import java.text.SimpleDateFormat
import java.util.*

data class InvoiceLineItemInput(
    val description: String = "",
    val amount: String = ""
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun InvoiceCreateScreen(
    merchantViewModel: MerchantViewModel,
    onPreview: (String) -> Unit,
    onBack: () -> Unit
) {
    val uiState by merchantViewModel.uiState.collectAsState()
    val context = LocalContext.current

    var memo by remember { mutableStateOf("") }
    var dueDateMillis by remember { mutableStateOf(System.currentTimeMillis() + 7 * 86400 * 1000) }
    var lineItems by remember {
        mutableStateOf(
            listOf(InvoiceLineItemInput())
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Create Invoice") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = {
                        val totalSats = lineItems.sumOf { parseGhostToSatoshis(it.amount) }
                        if (totalSats > 0) {
                            val dueDateUnix = dueDateMillis / 1000
                            val items = lineItems
                                .filter { it.description.isNotBlank() && parseGhostToSatoshis(it.amount) > 0 }
                                .map { Pair(it.description, parseGhostToSatoshis(it.amount)) }
                            val invoiceId = merchantViewModel.createInvoice(
                                totalAmount = totalSats,
                                dueDate = dueDateUnix,
                                lineItems = items,
                                memo = memo.ifBlank { null }
                            )
                            onPreview(invoiceId)
                        }
                    }) {
                        Text("Preview", color = MaterialTheme.colorScheme.primary)
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
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Invoice Details",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }

            // Due date picker
            item {
                val dateFormat = SimpleDateFormat("MMMM dd, yyyy", Locale.getDefault())
                val dateString = dateFormat.format(Date(dueDateMillis))

                OutlinedCard(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            showDatePicker(context, dueDateMillis) { selectedMillis ->
                                dueDateMillis = selectedMillis
                            }
                        },
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(
                                text = "Due Date",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                text = dateString,
                                style = MaterialTheme.typography.bodyLarge,
                                fontWeight = FontWeight.Medium
                            )
                        }
                        Text(
                            text = "Change",
                            color = MaterialTheme.colorScheme.primary,
                            style = MaterialTheme.typography.labelLarge
                        )
                    }
                }
            }

            // Memo
            item {
                OutlinedTextField(
                    value = memo,
                    onValueChange = { memo = it },
                    label = { Text("Notes / Memo (Optional)") },
                    placeholder = { Text("Add notes for the customer") },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 2,
                    maxLines = 4,
                    shape = RoundedCornerShape(12.dp)
                )
            }

            // Line items header
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Line Items",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    TextButton(onClick = {
                        lineItems = lineItems + InvoiceLineItemInput()
                    }) {
                        Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Add Item")
                    }
                }
            }

            // Line item rows
            itemsIndexed(lineItems) { index, item ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        verticalAlignment = Alignment.Top,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = item.description,
                            onValueChange = { newDesc ->
                                lineItems = lineItems.toMutableList().apply {
                                    this[index] = item.copy(description = newDesc)
                                }
                            },
                            label = { Text("Description") },
                            modifier = Modifier.weight(2f),
                            singleLine = true,
                            shape = RoundedCornerShape(8.dp)
                        )
                        OutlinedTextField(
                            value = item.amount,
                            onValueChange = { newAmt ->
                                lineItems = lineItems.toMutableList().apply {
                                    this[index] = item.copy(amount = newAmt)
                                }
                            },
                            label = { Text("GHOST") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            shape = RoundedCornerShape(8.dp)
                        )
                        if (lineItems.size > 1) {
                            IconButton(
                                onClick = {
                                    lineItems = lineItems.toMutableList().apply {
                                        removeAt(index)
                                    }
                                }
                            ) {
                                Icon(
                                    Icons.Filled.Delete,
                                    contentDescription = "Remove",
                                    tint = MaterialTheme.colorScheme.error
                                )
                            }
                        }
                    }
                }
            }

            // Total
            item {
                val totalSats = lineItems.sumOf { parseGhostToSatoshis(it.amount) }
                Divider()
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "Total",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = formatGhostFromSats(totalSats),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            }

            // Share button
            item {
                Button(
                    onClick = {
                        val totalSats = lineItems.sumOf { parseGhostToSatoshis(it.amount) }
                        if (totalSats > 0) {
                            val dueDateUnix = dueDateMillis / 1000
                            val items = lineItems
                                .filter { it.description.isNotBlank() && parseGhostToSatoshis(it.amount) > 0 }
                                .map { Pair(it.description, parseGhostToSatoshis(it.amount)) }
                            val invoiceId = merchantViewModel.createInvoice(
                                totalAmount = totalSats,
                                dueDate = dueDateUnix,
                                lineItems = items,
                                memo = memo.ifBlank { null }
                            )
                            val html = merchantViewModel.getInvoiceHtml(invoiceId)
                            shareInvoice(context, html)
                        }
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(52.dp),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Icon(Icons.Filled.Share, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Create & Share", fontWeight = FontWeight.Bold)
                }
            }

            item { Spacer(modifier = Modifier.height(24.dp)) }
        }
    }
}

private fun showDatePicker(
    context: Context,
    currentMillis: Long,
    onDateSelected: (Long) -> Unit
) {
    val calendar = Calendar.getInstance().apply { timeInMillis = currentMillis }
    DatePickerDialog(
        context,
        { _, year, month, day ->
            val selected = Calendar.getInstance().apply {
                set(year, month, day, 0, 0, 0)
                set(Calendar.MILLISECOND, 0)
            }
            onDateSelected(selected.timeInMillis)
        },
        calendar.get(Calendar.YEAR),
        calendar.get(Calendar.MONTH),
        calendar.get(Calendar.DAY_OF_MONTH)
    ).show()
}

private fun parseGhostToSatoshis(input: String): Long {
    return try {
        val amount = input.toDouble()
        (amount * 100_000_000).toLong()
    } catch (e: NumberFormatException) {
        0L
    }
}

private fun formatGhostFromSats(satoshis: Long): String {
    val whole = satoshis / 100_000_000
    val frac = satoshis % 100_000_000
    return "$whole.${"%08d".format(frac)} GHOST"
}

private fun shareInvoice(context: Context, html: String) {
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/html"
        putExtra(Intent.EXTRA_SUBJECT, "GhostTap Invoice")
        putExtra(Intent.EXTRA_HTML_TEXT, html)
        putExtra(Intent.EXTRA_TEXT, "Your GhostTap invoice is attached.")
    }
    context.startActivity(Intent.createChooser(intent, "Share Invoice"))
}
