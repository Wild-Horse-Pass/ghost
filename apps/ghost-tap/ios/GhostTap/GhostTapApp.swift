import SwiftUI

@main
struct GhostTapApp: App {
    @StateObject private var walletVM = WalletViewModel()
    @Environment(\.scenePhase) private var scenePhase

    init() {
        // Initialize Rust core
        do {
            try ghostTapInit()
            print("GhostTap Core initialized: v\(ghostTapVersion())")
        } catch {
            fatalError("Failed to initialize GhostTap Core: \(error)")
        }
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(walletVM)
                .onChange(of: scenePhase) { newPhase in
                    switch newPhase {
                    case .active:
                        walletVM.checkAutoLock()
                    case .background:
                        walletVM.recordActivity()
                    default:
                        break
                    }
                }
        }
    }
}

/// Root view that switches between onboarding and the main wallet based on
/// whether a wallet has been created/imported.
struct RootView: View {
    @EnvironmentObject private var vm: WalletViewModel
    @State private var showPinEntry = false
    @State private var showJailbreakWarning = JailbreakDetector.isJailbroken()

    var body: some View {
        ZStack {
            NavigationStack {
                if vm.hasWallet {
                    HomeView()
                        .environmentObject(vm)
                } else {
                    OnboardingView()
                        .environmentObject(vm)
                }
            }

            if vm.isLocked && hasPin() {
                PinEntryView(onUnlocked: {
                    showPinEntry = false
                })
                .environmentObject(vm)
                .transition(.opacity)
            }
        }
        .alert("Security Warning", isPresented: $showJailbreakWarning) {
            Button("I Understand", role: .cancel) {}
        } message: {
            Text("This device appears to be jailbroken. Your wallet keys may be at risk. Proceed with caution.")
        }
    }
}

/// Landing screen shown when no wallet exists.
/// Offers Create and Import paths.
struct OnboardingView: View {
    @EnvironmentObject private var vm: WalletViewModel

    @State private var navigateToCreate = false
    @State private var navigateToImport = false

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "wallet.pass")
                .font(.system(size: 80))
                .foregroundStyle(.tint)

            Text("GhostTap")
                .font(.largeTitle)
                .bold()

            Text("Tap. Pay. Ghost.")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            Spacer()

            VStack(spacing: 16) {
                Button {
                    navigateToCreate = true
                } label: {
                    Text("Create New Wallet")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)

                Button {
                    navigateToImport = true
                } label: {
                    Text("Import Existing Wallet")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .controlSize(.large)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 48)
        }
        .navigationTitle("")
        .navigationBarHidden(true)
        .navigationDestination(isPresented: $navigateToCreate) {
            WalletCreateView()
                .environmentObject(vm)
        }
        .navigationDestination(isPresented: $navigateToImport) {
            WalletImportView()
                .environmentObject(vm)
        }
    }
}

#Preview {
    RootView()
        .environmentObject(WalletViewModel())
}
