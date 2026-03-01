import SwiftUI

/// Merchant-specific settings: auto-wash toggle, ring size, receipt defaults.
struct MerchantSettingsView: View {
    @EnvironmentObject private var vm: MerchantViewModel

    var body: some View {
        Form {
            // Wraith wash
            Section {
                Toggle("Auto-Wash Payments", isOn: Binding(
                    get: { vm.autoWashEnabled },
                    set: { vm.setAutoWash($0) }
                ))

                if vm.autoWashEnabled {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Ring Size")
                            Spacer()
                            Text("\(vm.ringSize)")
                                .fontWeight(.bold)
                                .foregroundStyle(Color.accentColor)
                        }

                        Slider(
                            value: Binding(
                                get: { Double(vm.ringSize) },
                                set: { vm.setRingSize(Int($0)) }
                            ),
                            in: 3...32,
                            step: 1
                        )

                        HStack {
                            Text("Min (3)")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                            Spacer()
                            Text("Default (12)")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                            Spacer()
                            Text("Max (32)")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } header: {
                Text("Wraith Wash")
            } footer: {
                Text("Automatically wash all incoming payments through the Wraith Protocol for enhanced privacy. Higher ring sizes provide more privacy but take longer.")
            }

            // Receipt settings
            Section {
                Toggle("Auto-Generate Receipts", isOn: Binding(
                    get: { vm.receiptAutoGenerate },
                    set: { vm.setReceiptAutoGenerate($0) }
                ))

                Toggle("Show Logo on Receipts", isOn: Binding(
                    get: { vm.receiptShowLogo },
                    set: { vm.setReceiptShowLogo($0) }
                ))
            } header: {
                Text("Receipts")
            } footer: {
                Text("When auto-generate is enabled, a receipt is created for every payment received.")
            }

            // Profile link
            Section {
                NavigationLink(destination: MerchantProfileView().environmentObject(vm)) {
                    Label("Business Profile", systemImage: "building.2")
                }
            }
        }
        .navigationTitle("Merchant Settings")
    }
}
