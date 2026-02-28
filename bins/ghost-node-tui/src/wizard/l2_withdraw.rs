use super::{FieldDef, FieldType, WizardState, WizardStepDef};

/// Create the L2 Withdraw / Reconcile Lock wizard.
#[allow(dead_code)]
///
/// 4 steps: Select lock → Destination address → Settlement class → Confirm
pub fn create() -> WizardState {
    WizardState::new(
        "Withdraw \u{2014} Reconcile Lock",
        vec![
            WizardStepDef {
                id: "lock",
                title: "Select Lock",
                description: "Choose which Ghost Lock to withdraw from.",
                fields: vec![FieldDef {
                    key: "lock_id",
                    label: "Lock ID",
                    field_type: FieldType::Text,
                }],
            },
            WizardStepDef {
                id: "address",
                title: "Destination",
                description: "Enter the L1 Bitcoin address for settlement.",
                fields: vec![FieldDef {
                    key: "destination_address",
                    label: "Bitcoin Address",
                    field_type: FieldType::Text,
                }],
            },
            WizardStepDef {
                id: "settlement",
                title: "Settlement",
                description: "Select the settlement class for this withdrawal.",
                fields: vec![FieldDef {
                    key: "settlement_class",
                    label: "Settlement Class",
                    field_type: FieldType::Select(vec![
                        ("standard", "Standard \u{2014} Next checkpoint (~10 min)"),
                        ("priority", "Priority \u{2014} Immediate inclusion"),
                        ("batch", "Batch \u{2014} Aggregate with others (lower fees)"),
                    ]),
                }],
            },
            WizardStepDef {
                id: "confirm",
                title: "Confirm",
                description: "Review and submit the withdrawal.",
                fields: vec![FieldDef {
                    key: "confirm_info",
                    label: "Ready",
                    field_type: FieldType::Info(
                        "Review your withdrawal details above.\n\n\
                         Press Enter to submit the withdrawal request.\n\
                         Settlement will occur according to the selected class."
                            .to_string(),
                    ),
                }],
            },
        ],
    )
}
