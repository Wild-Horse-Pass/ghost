use super::{FieldDef, FieldType, WizardState, WizardStepDef};

pub fn create() -> WizardState {
    WizardState::new(
        "Build & Run",
        vec![
            WizardStepDef {
                id: "preflight",
                title: "Pre-flight",
                description: "Verify node readiness before taking action.",
                fields: vec![FieldDef {
                    key: "preflight_info",
                    label: "Pre-flight",
                    field_type: FieldType::Info("Running pre-flight checks...".to_string()),
                }],
            },
            WizardStepDef {
                id: "action",
                title: "Action",
                description: "Select the action to perform on your node.",
                fields: vec![FieldDef {
                    key: "action",
                    label: "Action",
                    field_type: FieldType::Select(vec![
                        ("restart", "Restart Node"),
                        ("stop", "Stop Node"),
                    ]),
                }],
            },
            WizardStepDef {
                id: "confirm",
                title: "Confirm",
                description: "Confirm the selected action.",
                fields: vec![FieldDef {
                    key: "confirm_info",
                    label: "Warning",
                    field_type: FieldType::Info(
                        "This action will affect your running node. Connected \
                         miners and peers will be temporarily disconnected. \
                         Press Enter to proceed."
                            .to_string(),
                    ),
                }],
            },
        ],
    )
}
