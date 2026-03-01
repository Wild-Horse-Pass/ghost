package com.ghost.tap.ui.screens.merchant

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.ghost.tap.viewmodel.MerchantViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MerchantProfileScreen(
    merchantViewModel: MerchantViewModel,
    onBack: () -> Unit
) {
    val uiState by merchantViewModel.uiState.collectAsState()

    var businessName by remember { mutableStateOf(uiState.businessName) }
    var businessAddress by remember { mutableStateOf(uiState.businessAddress) }
    var taxId by remember { mutableStateOf(uiState.taxId) }
    var ghostAddress by remember { mutableStateOf(uiState.ghostAddress) }
    var hasChanges by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Business Profile") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    if (hasChanges) {
                        TextButton(onClick = {
                            merchantViewModel.updateProfile(
                                businessName = businessName,
                                businessAddress = businessAddress,
                                taxId = taxId.ifBlank { null },
                                ghostAddress = ghostAddress
                            )
                            hasChanges = false
                        }) {
                            Text("Save")
                        }
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
            // Logo placeholder
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(
                        Icons.Filled.AccountCircle,
                        contentDescription = "Business Logo",
                        modifier = Modifier.size(72.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    TextButton(onClick = {
                        // Logo picker placeholder - would open image picker
                    }) {
                        Text("Change Logo")
                    }
                }
            }

            // Business info fields
            Text(
                text = "Business Information",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )

            OutlinedTextField(
                value = businessName,
                onValueChange = {
                    businessName = it
                    hasChanges = true
                },
                label = { Text("Business Name") },
                placeholder = { Text("e.g., Ghost Coffee Shop") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                shape = RoundedCornerShape(12.dp)
            )

            OutlinedTextField(
                value = businessAddress,
                onValueChange = {
                    businessAddress = it
                    hasChanges = true
                },
                label = { Text("Business Address") },
                placeholder = { Text("123 Main St, City, Country") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 2,
                maxLines = 3,
                shape = RoundedCornerShape(12.dp)
            )

            OutlinedTextField(
                value = taxId,
                onValueChange = {
                    taxId = it
                    hasChanges = true
                },
                label = { Text("Tax ID (Optional)") },
                placeholder = { Text("e.g., US-123456789") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                shape = RoundedCornerShape(12.dp)
            )

            Divider(modifier = Modifier.padding(vertical = 8.dp))

            Text(
                text = "Payment Settings",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )

            OutlinedTextField(
                value = ghostAddress,
                onValueChange = {
                    ghostAddress = it
                    hasChanges = true
                },
                label = { Text("Ghost Receive Address") },
                placeholder = { Text("Your Ghost address for receiving payments") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                shape = RoundedCornerShape(12.dp)
            )

            if (uiState.profileCreatedAt > 0) {
                Text(
                    text = "Profile created: ${formatDate(uiState.profileCreatedAt)}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

private fun formatDate(timestamp: Long): String {
    val date = java.util.Date(timestamp * 1000)
    val format = java.text.SimpleDateFormat("MMMM dd, yyyy", java.util.Locale.getDefault())
    return format.format(date)
}
