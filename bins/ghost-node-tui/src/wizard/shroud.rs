use super::{FieldDef, FieldType, WizardState, WizardStepDef};

pub fn create() -> WizardState {
    WizardState::new(
        "Ghost Shroud",
        vec![
            WizardStepDef {
                id: "status",
                title: "About Shroud",
                description: "Configure transaction relay privacy features.",
                fields: vec![FieldDef {
                    key: "status_info",
                    label: "Ghost Shroud",
                    field_type: FieldType::Info(
                        "Ghost Shroud provides relay-level privacy by obscuring \
                         the origin of transactions through delayed and randomized \
                         relay paths. Dandelion++ support adds stem-phase routing \
                         before fluff-phase broadcast."
                            .to_string(),
                    ),
                }],
            },
            WizardStepDef {
                id: "config",
                title: "Configuration",
                description: "Configure Shroud relay privacy settings.",
                fields: vec![
                    FieldDef {
                        key: "enabled",
                        label: "Enable Shroud",
                        field_type: FieldType::Toggle,
                    },
                    FieldDef {
                        key: "dandelion",
                        label: "Enable Dandelion++",
                        field_type: FieldType::Toggle,
                    },
                    FieldDef {
                        key: "max_delay_ms",
                        label: "Max Relay Delay (ms)",
                        field_type: FieldType::Text,
                    },
                ],
            },
            WizardStepDef {
                id: "confirm",
                title: "Confirm",
                description: "Apply Shroud configuration.",
                fields: vec![FieldDef {
                    key: "confirm_info",
                    label: "Summary",
                    field_type: FieldType::Info(
                        "Press Enter to apply Shroud relay privacy settings.".to_string(),
                    ),
                }],
            },
        ],
    )
}
