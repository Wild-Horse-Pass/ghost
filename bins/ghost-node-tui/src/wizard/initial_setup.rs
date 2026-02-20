use super::{FieldDef, FieldType, WizardState, WizardStepDef};

pub fn create() -> WizardState {
    WizardState::new(
        "Initial Node Setup",
        vec![
            WizardStepDef {
                id: "welcome",
                title: "Welcome",
                description: "Get started with Ghost Pool.",
                fields: vec![FieldDef {
                    key: "welcome_info",
                    label: "Welcome",
                    field_type: FieldType::Info(
                        "Welcome to Ghost Pool! This wizard will guide you through \
                         initial configuration."
                            .to_string(),
                    ),
                }],
            },
            WizardStepDef {
                id: "identity",
                title: "Node Identity",
                description: "Set a name for your node on the network.",
                fields: vec![FieldDef {
                    key: "nickname",
                    label: "Node Nickname",
                    field_type: FieldType::Text,
                }],
            },
            WizardStepDef {
                id: "mining",
                title: "Mining",
                description: "Configure mining and payout settings.",
                fields: vec![
                    FieldDef {
                        key: "public_mining",
                        label: "Enable Public Mining",
                        field_type: FieldType::Toggle,
                    },
                    FieldDef {
                        key: "payout_address",
                        label: "Payout Address",
                        field_type: FieldType::Text,
                    },
                ],
            },
            WizardStepDef {
                id: "modes",
                title: "Node Modes",
                description: "Enable optional node capabilities.",
                fields: vec![
                    FieldDef {
                        key: "ghost_mode",
                        label: "Ghost Mode",
                        field_type: FieldType::Toggle,
                    },
                    FieldDef {
                        key: "archive_mode",
                        label: "Archive Mode",
                        field_type: FieldType::Toggle,
                    },
                    FieldDef {
                        key: "bitcoin_pure",
                        label: "Bitcoin Pure",
                        field_type: FieldType::Toggle,
                    },
                    FieldDef {
                        key: "ghost_pay",
                        label: "Ghost Pay",
                        field_type: FieldType::Toggle,
                    },
                ],
            },
            WizardStepDef {
                id: "profile",
                title: "Mempool Profile",
                description: "Select a mempool acceptance policy.",
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
                id: "confirm",
                title: "Confirm",
                description: "Finalize your initial node configuration.",
                fields: vec![FieldDef {
                    key: "confirm_info",
                    label: "Review",
                    field_type: FieldType::Info(
                        "Review your configuration: press Enter to apply, \
                         or Esc to go back and make changes."
                            .to_string(),
                    ),
                }],
            },
        ],
    )
}
