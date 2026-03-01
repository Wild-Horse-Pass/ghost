package com.ghost.tap.ui.screens.merchant

import android.app.DatePickerDialog
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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

private enum class ExportFormat {
    CSV, PDF
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TransactionExportScreen(
    merchantViewModel: MerchantViewModel,
    onBack: () -> Unit
) {
    val uiState by merchantViewModel.uiState.collectAsState()
    val context = LocalContext.current

    // Default range: last 30 days
    val now = System.currentTimeMillis()
    var startDateMillis by remember { mutableStateOf(now - 30L * 86400 * 1000) }
    var endDateMillis by remember { mutableStateOf(now) }
    var selectedFormat by remember { mutableStateOf(ExportFormat.CSV) }
    var isExporting by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Export Transactions") },
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
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                text = "Date Range",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )

            // Start date
            DatePickerField(
                label = "Start Date",
                dateMillis = startDateMillis,
                context = context,
                onDateSelected = { startDateMillis = it }
            )

            // End date
            DatePickerField(
                label = "End Date",
                dateMillis = endDateMillis,
                context = context,
                onDateSelected = { endDateMillis = it }
            )

            Divider(modifier = Modifier.padding(vertical = 8.dp))

            Text(
                text = "Format",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )

            // Format selection
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                FormatCard(
                    label = "CSV",
                    description = "Spreadsheet-compatible",
                    selected = selectedFormat == ExportFormat.CSV,
                    onClick = { selectedFormat = ExportFormat.CSV },
                    modifier = Modifier.weight(1f)
                )
                FormatCard(
                    label = "PDF",
                    description = "Printable report",
                    selected = selectedFormat == ExportFormat.PDF,
                    onClick = { selectedFormat = ExportFormat.PDF },
                    modifier = Modifier.weight(1f)
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Transaction count in range
            val fromUnix = startDateMillis / 1000
            val toUnix = endDateMillis / 1000
            val txCount = merchantViewModel.getTransactionCountInRange(fromUnix, toUnix)

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                ),
                shape = RoundedCornerShape(12.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text("Transactions in range:")
                    Text(
                        text = "$txCount",
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            }

            Spacer(modifier = Modifier.weight(1f))

            // Generate & share
            Button(
                onClick = {
                    isExporting = true
                    val content = when (selectedFormat) {
                        ExportFormat.CSV -> {
                            merchantViewModel.exportCsv(fromUnix, toUnix)
                        }
                        ExportFormat.PDF -> {
                            merchantViewModel.exportHtmlReport(fromUnix, toUnix)
                        }
                    }
                    val mimeType = when (selectedFormat) {
                        ExportFormat.CSV -> "text/csv"
                        ExportFormat.PDF -> "text/html"
                    }
                    shareExport(context, content, mimeType, selectedFormat.name)
                    isExporting = false
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp),
                shape = RoundedCornerShape(16.dp),
                enabled = !isExporting && txCount > 0
            ) {
                if (isExporting) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                }
                Icon(Icons.Filled.Share, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Generate & Share ${selectedFormat.name}",
                    fontWeight = FontWeight.Bold
                )
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Composable
private fun DatePickerField(
    label: String,
    dateMillis: Long,
    context: Context,
    onDateSelected: (Long) -> Unit
) {
    val dateFormat = SimpleDateFormat("MMMM dd, yyyy", Locale.getDefault())
    val dateString = dateFormat.format(Date(dateMillis))

    OutlinedCard(
        modifier = Modifier
            .fillMaxWidth()
            .clickable {
                val calendar = Calendar.getInstance().apply { timeInMillis = dateMillis }
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
                    text = label,
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

@Composable
private fun FormatCard(
    label: String,
    description: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val containerColor = if (selected) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.surfaceVariant
    }
    val contentColor = if (selected) {
        MaterialTheme.colorScheme.onPrimaryContainer
    } else {
        MaterialTheme.colorScheme.onSurfaceVariant
    }

    Card(
        modifier = modifier.clickable(onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = containerColor),
        shape = RoundedCornerShape(12.dp),
        border = if (selected) {
            CardDefaults.outlinedCardBorder()
        } else null
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = contentColor
            )
            Text(
                text = description,
                style = MaterialTheme.typography.labelSmall,
                color = contentColor.copy(alpha = 0.7f)
            )
        }
    }
}

private fun shareExport(
    context: Context,
    content: String,
    mimeType: String,
    formatName: String
) {
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = mimeType
        putExtra(Intent.EXTRA_SUBJECT, "GhostTap Transaction Export ($formatName)")
        putExtra(Intent.EXTRA_TEXT, content)
    }
    context.startActivity(Intent.createChooser(intent, "Share Export"))
}
