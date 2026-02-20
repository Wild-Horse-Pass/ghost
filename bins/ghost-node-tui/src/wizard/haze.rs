use super::{FieldDef, FieldType, WizardState, WizardStepDef};

pub fn create() -> WizardState {
    WizardState::new(
        "Ghost Haze",
        vec![
            WizardStepDef {
                id: "status",
                title: "About Ghost Haze",
                description: "Configure block storage and witness stripping.",
                fields: vec![FieldDef {
                    key: "status_info",
                    label: "Ghost Haze",
                    field_type: FieldType::Info(
                        "Ghost Haze controls how your node stores block data. \
                         Hazed mode strips witness and script data to reduce \
                         disk usage while maintaining block validity proofs."
                            .to_string(),
                    ),
                }],
            },
            WizardStepDef {
                id: "mode",
                title: "Storage Mode",
                description: "Select your preferred block storage mode.",
                fields: vec![FieldDef {
                    key: "haze_mode",
                    label: "Haze Mode",
                    field_type: FieldType::Select(vec![
                        ("standard", "Standard \u{2014} Normal block storage"),
                        ("hazed", "Hazed \u{2014} Strip witness/script data"),
                        ("full_archive", "Full Archive \u{2014} Keep full blocks"),
                    ]),
                }],
            },
            WizardStepDef {
                id: "confirm",
                title: "Confirm",
                description: "Apply Ghost Haze configuration.",
                fields: vec![FieldDef {
                    key: "confirm_info",
                    label: "Summary",
                    field_type: FieldType::Info(
                        "Press Enter to apply Ghost Haze storage mode.".to_string(),
                    ),
                }],
            },
        ],
    )
}
