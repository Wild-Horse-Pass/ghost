import SwiftUI

/// Business profile editor for merchant mode.
struct MerchantProfileView: View {
    @EnvironmentObject private var vm: MerchantViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var businessName: String = ""
    @State private var businessAddress: String = ""
    @State private var taxId: String = ""
    @State private var ghostAddress: String = ""
    @State private var hasChanges: Bool = false

    var body: some View {
        Form {
            // Logo section
            Section {
                HStack {
                    Spacer()
                    VStack(spacing: 8) {
                        Image(systemName: "building.2.fill")
                            .font(.system(size: 48))
                            .foregroundStyle(.secondary)

                        Button("Change Logo") {
                            // Logo picker placeholder
                        }
                        .font(.subheadline)
                    }
                    Spacer()
                }
                .listRowBackground(Color.clear)
            }

            // Business information
            Section("Business Information") {
                TextField("Business Name", text: $businessName)
                    .onChange(of: businessName) { _ in hasChanges = true }

                TextField("Business Address", text: $businessAddress, axis: .vertical)
                    .lineLimit(2...4)
                    .onChange(of: businessAddress) { _ in hasChanges = true }

                TextField("Tax ID (Optional)", text: $taxId)
                    .onChange(of: taxId) { _ in hasChanges = true }
            }

            // Payment settings
            Section("Payment Settings") {
                TextField("Ghost Receive Address", text: $ghostAddress)
                    .font(.system(.body, design: .monospaced))
                    .onChange(of: ghostAddress) { _ in hasChanges = true }
            }

            // Profile metadata
            if vm.profileCreatedAt > 0 {
                Section {
                    HStack {
                        Text("Profile Created")
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text(formatDate(vm.profileCreatedAt))
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .navigationTitle("Business Profile")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                if hasChanges {
                    Button("Save") {
                        vm.updateProfile(
                            businessName: businessName,
                            businessAddress: businessAddress,
                            taxId: taxId.isEmpty ? nil : taxId,
                            ghostAddress: ghostAddress
                        )
                        hasChanges = false
                    }
                    .fontWeight(.bold)
                }
            }
        }
        .onAppear {
            businessName = vm.businessName
            businessAddress = vm.businessAddress
            taxId = vm.taxId ?? ""
            ghostAddress = vm.ghostAddress
        }
    }

    private func formatDate(_ timestamp: UInt64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(timestamp))
        let formatter = DateFormatter()
        formatter.dateStyle = .long
        return formatter.string(from: date)
    }
}
