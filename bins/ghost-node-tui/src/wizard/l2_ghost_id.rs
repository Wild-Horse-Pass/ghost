use super::{FieldDef, FieldType, WizardState, WizardStepDef};

/// Create the Ghost ID wizard.
#[allow(dead_code)]
///
/// 3 steps: Info → Generate → Display
pub fn create() -> WizardState {
    WizardState::new(
        "Ghost ID \u{2014} L2 Identity",
        vec![
            WizardStepDef {
                id: "info",
                title: "Ghost ID",
                description: "Create a new Ghost ID for L2 transactions.",
                fields: vec![FieldDef {
                    key: "info_text",
                    label: "About Ghost ID",
                    field_type: FieldType::Info(
                        "A Ghost ID is your pseudonymous identity on the L2 network.\n\n\
                         It is derived from your node keys and used to:\n\
                         \u{2022} Receive L2 payments\n\
                         \u{2022} Create and manage Ghost Locks\n\
                         \u{2022} Sign L2 transactions\n\n\
                         Press Enter to generate a new Ghost ID."
                            .to_string(),
                    ),
                }],
            },
            WizardStepDef {
                id: "generate",
                title: "Generate",
                description: "Configure your Ghost ID label.",
                fields: vec![FieldDef {
                    key: "ghost_id_label",
                    label: "Label (optional)",
                    field_type: FieldType::Text,
                }],
            },
            WizardStepDef {
                id: "confirm",
                title: "Confirm",
                description: "Review and create your Ghost ID.",
                fields: vec![FieldDef {
                    key: "confirm_info",
                    label: "Ready",
                    field_type: FieldType::Info(
                        "Press Enter to generate your Ghost ID.\n\
                         Your ID will be derived from your node keypair."
                            .to_string(),
                    ),
                }],
            },
        ],
    )
}
