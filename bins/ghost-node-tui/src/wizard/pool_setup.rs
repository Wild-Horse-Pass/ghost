use super::{FieldDef, FieldType, WizardState, WizardStepDef};

pub fn create() -> WizardState {
    WizardState::new(
        "pool_setup",
        "Setting Up a Pool",
        vec![
            WizardStepDef {
                id: "mining",
                title: "Mining Configuration",
                description: "Configure your node as a public mining pool.",
                fields: vec![FieldDef {
                    key: "public_mining",
                    label: "Enable Public Mining",
                    field_type: FieldType::Toggle,
                }],
            },
            WizardStepDef {
                id: "address",
                title: "Payout Address",
                description: "Set the payout address for mining rewards.",
                fields: vec![FieldDef {
                    key: "payout_address",
                    label: "Payout Address (bech32)",
                    field_type: FieldType::Text,
                }],
            },
            WizardStepDef {
                id: "info",
                title: "Summary",
                description: "Review your pool configuration.",
                fields: vec![FieldDef {
                    key: "info_summary",
                    label: "Pool Setup",
                    field_type: FieldType::Info(
                        "Your pool will be configured with the settings above. \
                         Miners will be able to connect via Stratum on port 3333."
                            .to_string(),
                    ),
                }],
            },
            WizardStepDef {
                id: "confirm",
                title: "Confirm",
                description: "Apply pool configuration.",
                fields: vec![FieldDef {
                    key: "confirm_info",
                    label: "Ready",
                    field_type: FieldType::Info("Ready to configure pool.".to_string()),
                }],
            },
        ],
    )
}
