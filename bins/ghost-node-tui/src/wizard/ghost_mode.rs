use super::{FieldDef, FieldType, WizardState, WizardStepDef};

pub fn create() -> WizardState {
    WizardState::new(
        "ghost_mode",
        "Ghost Mode",
        vec![
            WizardStepDef {
                id: "status",
                title: "Current Status",
                description: "Ghost Mode enhances your node with privacy and stealth features.",
                fields: vec![FieldDef {
                    key: "status_info",
                    label: "Status",
                    field_type: FieldType::Info(
                        "Ghost Mode is currently disabled. Enable it to activate \
                         privacy-enhanced transaction relay, stealth addressing, \
                         and mempool obfuscation."
                            .to_string(),
                    ),
                }],
            },
            WizardStepDef {
                id: "toggle",
                title: "Enable/Disable",
                description: "Toggle Ghost Mode on or off for this node.",
                fields: vec![FieldDef {
                    key: "ghost_mode",
                    label: "Enable Ghost Mode",
                    field_type: FieldType::Toggle,
                }],
            },
            WizardStepDef {
                id: "confirm",
                title: "Confirm",
                description: "Review your selection before applying.",
                fields: vec![FieldDef {
                    key: "confirm_info",
                    label: "Summary",
                    field_type: FieldType::Info(
                        "Press Enter to apply Ghost Mode configuration.".to_string(),
                    ),
                }],
            },
        ],
    )
}
