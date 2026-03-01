package com.ghost.tap

import androidx.compose.runtime.Composable
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.ghost.tap.ui.screens.*
import com.ghost.tap.viewmodel.WalletViewModel

sealed class Screen(val route: String) {
    data object Onboarding : Screen("onboarding")
    data object Home : Screen("home")
    data object Send : Screen("send")
    data object Receive : Screen("receive")
    data object WalletCreate : Screen("wallet_create")
    data object MnemonicBackup : Screen("mnemonic_backup/{mnemonic}") {
        fun createRoute(mnemonic: String): String =
            "mnemonic_backup/${java.net.URLEncoder.encode(mnemonic, "UTF-8")}"
    }
    data object MnemonicVerify : Screen("mnemonic_verify/{mnemonic}") {
        fun createRoute(mnemonic: String): String =
            "mnemonic_verify/${java.net.URLEncoder.encode(mnemonic, "UTF-8")}"
    }
    data object WalletImport : Screen("wallet_import")
    data object TransactionDetail : Screen("transaction_detail/{txId}") {
        fun createRoute(txId: String): String = "transaction_detail/$txId"
    }
    data object Settings : Screen("settings")
    data object QrScanner : Screen("qr_scanner")
    data object PinSetup : Screen("pin_setup")
    data object PinEntry : Screen("pin_entry")
}

@Composable
fun GhostTapNavigation(
    navController: NavHostController = rememberNavController(),
    walletViewModel: WalletViewModel = viewModel()
) {
    NavHost(
        navController = navController,
        startDestination = Screen.Onboarding.route
    ) {
        composable(Screen.Onboarding.route) {
            OnboardingScreen(
                onCreateWallet = {
                    navController.navigate(Screen.WalletCreate.route)
                },
                onImportWallet = {
                    navController.navigate(Screen.WalletImport.route)
                }
            )
        }

        composable(Screen.WalletCreate.route) {
            WalletCreateScreen(
                walletViewModel = walletViewModel,
                onMnemonicGenerated = { mnemonic ->
                    navController.navigate(Screen.MnemonicBackup.createRoute(mnemonic)) {
                        popUpTo(Screen.WalletCreate.route) { inclusive = true }
                    }
                },
                onBack = { navController.popBackStack() }
            )
        }

        composable(
            route = Screen.MnemonicBackup.route,
            arguments = listOf(navArgument("mnemonic") { type = NavType.StringType })
        ) { backStackEntry ->
            val mnemonic = java.net.URLDecoder.decode(
                backStackEntry.arguments?.getString("mnemonic") ?: "", "UTF-8"
            )
            MnemonicBackupScreen(
                mnemonic = mnemonic,
                onProceedToVerify = {
                    navController.navigate(Screen.MnemonicVerify.createRoute(mnemonic)) {
                        popUpTo(Screen.MnemonicBackup.route) { inclusive = true }
                    }
                },
                onBack = { navController.popBackStack() }
            )
        }

        composable(
            route = Screen.MnemonicVerify.route,
            arguments = listOf(navArgument("mnemonic") { type = NavType.StringType })
        ) { backStackEntry ->
            val mnemonic = java.net.URLDecoder.decode(
                backStackEntry.arguments?.getString("mnemonic") ?: "", "UTF-8"
            )
            MnemonicVerifyScreen(
                mnemonic = mnemonic,
                walletViewModel = walletViewModel,
                onVerified = {
                    navController.navigate(Screen.PinSetup.route) {
                        popUpTo(Screen.Onboarding.route) { inclusive = true }
                    }
                },
                onBack = { navController.popBackStack() }
            )
        }

        composable(Screen.WalletImport.route) {
            WalletImportScreen(
                walletViewModel = walletViewModel,
                onImportSuccess = {
                    navController.navigate(Screen.Home.route) {
                        popUpTo(Screen.Onboarding.route) { inclusive = true }
                    }
                },
                onBack = { navController.popBackStack() }
            )
        }

        composable(Screen.Home.route) {
            HomeScreen(
                walletViewModel = walletViewModel,
                onSend = { navController.navigate(Screen.Send.route) },
                onReceive = { navController.navigate(Screen.Receive.route) },
                onScan = { navController.navigate(Screen.QrScanner.route) },
                onTransactionClick = { txId ->
                    navController.navigate(Screen.TransactionDetail.createRoute(txId))
                },
                onSettings = { navController.navigate(Screen.Settings.route) }
            )
        }

        composable(Screen.Send.route) {
            SendScreen(
                walletViewModel = walletViewModel,
                onBack = { navController.popBackStack() },
                onSent = { navController.popBackStack() }
            )
        }

        composable(Screen.Receive.route) {
            ReceiveScreen(
                walletViewModel = walletViewModel,
                onBack = { navController.popBackStack() }
            )
        }

        composable(
            route = Screen.TransactionDetail.route,
            arguments = listOf(navArgument("txId") { type = NavType.StringType })
        ) { backStackEntry ->
            val txId = backStackEntry.arguments?.getString("txId") ?: ""
            TransactionDetailScreen(
                txId = txId,
                walletViewModel = walletViewModel,
                onBack = { navController.popBackStack() }
            )
        }

        composable(Screen.Settings.route) {
            SettingsScreen(
                onBack = { navController.popBackStack() }
            )
        }

        composable(Screen.PinSetup.route) {
            PinSetupScreen(
                onPinSet = {
                    navController.navigate(Screen.Home.route) {
                        popUpTo(Screen.Onboarding.route) { inclusive = true }
                    }
                },
                onBack = { navController.popBackStack() }
            )
        }

        composable(Screen.PinEntry.route) {
            PinEntryScreen(
                onUnlocked = {
                    navController.popBackStack()
                },
                remainingAttempts = try {
                    com.ghost.tap.RustBridge.pinRemainingAttempts()
                } catch (_: Exception) { 5 }
            )
        }

        composable(Screen.QrScanner.route) {
            QrScannerScreen(
                onCodeScanned = { code ->
                    navController.popBackStack()
                    // Navigate to send with scanned address pre-filled
                    navController.navigate(Screen.Send.route)
                },
                onBack = { navController.popBackStack() }
            )
        }
    }
}
