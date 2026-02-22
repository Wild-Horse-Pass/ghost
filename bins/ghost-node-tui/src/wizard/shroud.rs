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
                        "Ghost Shroud provides relay-level privacy by adding a random \
                         0-5 second delay before relaying transactions to peers. This \
                         makes it harder for network observers to determine the origin \
                         of a transaction. Requires a ghost-core restart to take effect."
                            .to_string(),
                    ),
                }],
            },
            WizardStepDef {
                id: "config",
                title: "Configuration",
                description: "Enable or disable Shroud relay privacy.",
                fields: vec![FieldDef {
                    key: "enabled",
                    label: "Enable Shroud",
                    field_type: FieldType::Toggle,
                }],
            },
            WizardStepDef {
                id: "confirm",
                title: "Confirm",
                description: "Apply Shroud configuration.",
                fields: vec![FieldDef {
                    key: "confirm_info",
                    label: "Summary",
                    field_type: FieldType::Info(
                        "Press Enter to apply. Ghost-core will need to be restarted \
                         for the change to take effect."
                            .to_string(),
                    ),
                }],
            },
        ],
    )
}
