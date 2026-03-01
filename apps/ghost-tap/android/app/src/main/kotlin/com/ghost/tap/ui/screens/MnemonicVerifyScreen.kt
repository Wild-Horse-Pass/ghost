package com.ghost.tap.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusDirection
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.ghost.tap.viewmodel.WalletViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MnemonicVerifyScreen(
    mnemonic: String,
    walletViewModel: WalletViewModel,
    onVerified: () -> Unit,
    onBack: () -> Unit
) {
    val words = remember { mnemonic.split(" ") }
    // Pick 3 random word indices to verify
    val challengeIndices = remember {
        (words.indices).shuffled().take(3).sorted()
    }

    var answer0 by remember { mutableStateOf("") }
    var answer1 by remember { mutableStateOf("") }
    var answer2 by remember { mutableStateOf("") }
    var hasAttempted by remember { mutableStateOf(false) }

    val focusManager = LocalFocusManager.current

    val answers = listOf(answer0, answer1, answer2)
    val allCorrect = challengeIndices.mapIndexed { i, wordIndex ->
        answers[i].trim().lowercase() == words[wordIndex].lowercase()
    }.all { it }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Verify Backup") },
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
                .padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = "Confirm Your Recovery Phrase",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "Enter the requested words from your recovery phrase to confirm you saved it correctly.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(32.dp))

            // Challenge fields
            challengeIndices.forEachIndexed { challengeIdx, wordIndex ->
                val currentAnswer = answers[challengeIdx]
                val isCorrect = currentAnswer.trim().lowercase() == words[wordIndex].lowercase()
                val showStatus = hasAttempted || currentAnswer.isNotBlank()

                OutlinedTextField(
                    value = currentAnswer,
                    onValueChange = { newVal ->
                        val filtered = newVal.filter { it.isLetter() }
                        when (challengeIdx) {
                            0 -> answer0 = filtered
                            1 -> answer1 = filtered
                            2 -> answer2 = filtered
                        }
                    },
                    label = { Text("Word #${wordIndex + 1}") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Text,
                        imeAction = if (challengeIdx < 2) ImeAction.Next else ImeAction.Done
                    ),
                    keyboardActions = KeyboardActions(
                        onNext = { focusManager.moveFocus(FocusDirection.Down) },
                        onDone = { focusManager.clearFocus() }
                    ),
                    trailingIcon = {
                        if (showStatus && currentAnswer.isNotBlank()) {
                            if (isCorrect) {
                                Icon(
                                    Icons.Default.CheckCircle,
                                    contentDescription = "Correct",
                                    tint = MaterialTheme.colorScheme.primary
                                )
                            } else if (hasAttempted) {
                                Icon(
                                    Icons.Default.Error,
                                    contentDescription = "Incorrect",
                                    tint = MaterialTheme.colorScheme.error
                                )
                            }
                        }
                    },
                    isError = hasAttempted && !isCorrect && currentAnswer.isNotBlank()
                )

                Spacer(modifier = Modifier.height(16.dp))
            }

            if (hasAttempted && !allCorrect) {
                Text(
                    text = "One or more words are incorrect. Please check your backup and try again.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    textAlign = TextAlign.Center
                )
                Spacer(modifier = Modifier.height(16.dp))
            }

            Spacer(modifier = Modifier.weight(1f))

            Button(
                onClick = {
                    hasAttempted = true
                    if (allCorrect) {
                        walletViewModel.finalizeWalletCreation(mnemonic)
                        onVerified()
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 24.dp),
                enabled = answers.all { it.isNotBlank() }
            ) {
                Text("Verify & Create Wallet")
            }
        }
    }
}
