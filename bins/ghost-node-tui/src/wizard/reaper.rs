use super::{FieldDef, FieldType, WizardState, WizardStepDef};

pub fn create() -> WizardState {
    WizardState::new(
        "reaper",
        "Reaper \u{2014} Mempool Policy",
        vec![
            WizardStepDef {
                id: "enable",
                title: "Reaper",
                description: "Enable Reaper mode to filter non-monetary transactions.",
                fields: vec![FieldDef {
                    key: "reaper",
                    label: "Enable Reaper",
                    field_type: FieldType::Toggle,
                }],
            },
            WizardStepDef {
                id: "filters",
                title: "Filter Configuration",
                description: "Configure individual mempool filters and limits.",
                fields: vec![
                    FieldDef {
                        key: "filter_inscriptions",
                        label: "Filter Inscriptions",
                        field_type: FieldType::Toggle,
                    },
                    FieldDef {
                        key: "filter_brc20",
                        label: "Filter BRC-20",
                        field_type: FieldType::Toggle,
                    },
                    FieldDef {
                        key: "filter_runes",
                        label: "Filter Runes",
                        field_type: FieldType::Toggle,
                    },
                    FieldDef {
                        key: "max_witness_size",
                        label: "Max Witness Size (bytes)",
                        field_type: FieldType::Text,
                    },
                    FieldDef {
                        key: "dust_limit",
                        label: "Dust Limit (sats)",
                        field_type: FieldType::Text,
                    },
                ],
            },
            WizardStepDef {
                id: "preview",
                title: "Preview",
                description: "Review your Reaper mempool policy configuration.",
                fields: vec![FieldDef {
                    key: "preview_info",
                    label: "Policy Summary",
                    field_type: FieldType::Info(
                        "Your selected filters and limits will be applied to the \
                         node mempool policy. Transactions matching these criteria \
                         will be rejected at relay time."
                            .to_string(),
                    ),
                }],
            },
            WizardStepDef {
                id: "confirm",
                title: "Confirm",
                description: "Apply the Reaper mempool policy.",
                fields: vec![FieldDef {
                    key: "confirm_info",
                    label: "Ready",
                    field_type: FieldType::Info("Ready to apply Reaper policy.".to_string()),
                }],
            },
        ],
    )
}
