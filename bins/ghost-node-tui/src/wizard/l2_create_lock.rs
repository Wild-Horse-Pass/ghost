use super::{FieldDef, FieldType, WizardState, WizardStepDef};

/// Create the Ghost Lock creation wizard.
#[allow(dead_code)]
///
/// 4 steps: Denomination → Timelock → Label → Confirm
pub fn create() -> WizardState {
    WizardState::new(
        "l2_create_lock",
        "Create Ghost Lock",
        vec![
            WizardStepDef {
                id: "denomination",
                title: "Denomination",
                description: "Select the lock denomination.",
                fields: vec![FieldDef {
                    key: "denomination",
                    label: "Lock Denomination",
                    field_type: FieldType::Select(vec![
                        ("micro", "Micro \u{2014} 10,000 sats"),
                        ("tiny", "Tiny \u{2014} 100,000 sats"),
                        ("small", "Small \u{2014} 1,000,000 sats"),
                        ("medium", "Medium \u{2014} 10,000,000 sats"),
                        ("large", "Large \u{2014} 100,000,000 sats"),
                    ]),
                }],
            },
            WizardStepDef {
                id: "timelock",
                title: "Timelock",
                description: "Select the lock duration.",
                fields: vec![FieldDef {
                    key: "timelock",
                    label: "Lock Duration",
                    field_type: FieldType::Select(vec![
                        ("1w", "1 week"),
                        ("1m", "1 month"),
                        ("3m", "3 months"),
                        ("6m", "6 months"),
                        ("1y", "1 year"),
                    ]),
                }],
            },
            WizardStepDef {
                id: "label",
                title: "Label",
                description: "Add an optional label for this lock.",
                fields: vec![FieldDef {
                    key: "lock_label",
                    label: "Lock Label (optional)",
                    field_type: FieldType::Text,
                }],
            },
            WizardStepDef {
                id: "confirm",
                title: "Confirm",
                description: "Review and create the Ghost Lock.",
                fields: vec![FieldDef {
                    key: "confirm_info",
                    label: "Ready",
                    field_type: FieldType::Info(
                        "Review your lock configuration above.\n\n\
                         Press Enter to create the Ghost Lock.\n\
                         The lock will be funded from your L2 balance."
                            .to_string(),
                    ),
                }],
            },
        ],
    )
}
