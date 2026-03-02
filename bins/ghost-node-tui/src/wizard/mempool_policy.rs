use super::{FieldDef, FieldType, WizardState, WizardStepDef};

pub fn create() -> WizardState {
    WizardState::new(
        "mempool_policy",
        "Mempool & Block Policy",
        vec![
            WizardStepDef {
                id: "mempool",
                title: "Mempool Profile",
                description: "Select a mempool acceptance profile for your node.",
                fields: vec![FieldDef {
                    key: "mempool_profile",
                    label: "Mempool Profile",
                    field_type: FieldType::Select(vec![
                        ("permissive", "Permissive \u{2014} Accept all standard"),
                        ("strict", "Strict \u{2014} Bitcoin Core defaults"),
                        ("custom", "Custom \u{2014} Manual configuration"),
                    ]),
                }],
            },
            WizardStepDef {
                id: "template",
                title: "Block Template",
                description: "Select a block template construction profile.",
                fields: vec![FieldDef {
                    key: "template_profile",
                    label: "Template Profile",
                    field_type: FieldType::Select(vec![
                        ("default", "Default \u{2014} Standard template"),
                        ("compact", "Compact \u{2014} Smaller blocks"),
                        ("maximum", "Maximum \u{2014} Max block size"),
                    ]),
                }],
            },
            WizardStepDef {
                id: "confirm",
                title: "Confirm",
                description: "Apply mempool and block policy.",
                fields: vec![FieldDef {
                    key: "confirm_info",
                    label: "Summary",
                    field_type: FieldType::Info(
                        "Press Enter to apply mempool and block policy settings.".to_string(),
                    ),
                }],
            },
        ],
    )
}
