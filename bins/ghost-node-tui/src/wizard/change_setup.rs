use super::{FieldDef, FieldType, FieldValue, WizardState, WizardStepDef};

pub fn create() -> WizardState {
    WizardState::new(
        "Change Node Setup",
        vec![
            WizardStepDef {
                id: "welcome",
                title: "Modify Configuration",
                description: "Update your existing node settings.",
                fields: vec![FieldDef {
                    key: "welcome_info",
                    label: "Info",
                    field_type: FieldType::Info(
                        "Modify your existing configuration. Only changed values \
                         will be submitted."
                            .to_string(),
                    ),
                }],
            },
            WizardStepDef {
                id: "identity",
                title: "Node Identity",
                description: "Change your node name on the network.",
                fields: vec![FieldDef {
                    key: "nickname",
                    label: "Node Nickname",
                    field_type: FieldType::Text,
                }],
            },
            WizardStepDef {
                id: "mining",
                title: "Mining",
                description: "Update mining and payout settings.",
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
                description: "Toggle optional node capabilities.",
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
                description: "Change your mempool acceptance policy.",
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
                description: "Finalize your configuration changes.",
                fields: vec![FieldDef {
                    key: "confirm_info",
                    label: "Review",
                    field_type: FieldType::Info(
                        "Review your changes: press Enter to apply, \
                         or Esc to go back and make changes."
                            .to_string(),
                    ),
                }],
            },
        ],
    )
}

/// Create a wizard pre-populated with values from existing configuration.
///
/// Expected JSON keys: `nickname` (string), `public_mining` (bool),
/// `payout_address` (string), `ghost_mode` (bool), `archive_mode` (bool),
/// `bitcoin_pure` (bool), `ghost_pay` (bool), `mempool_profile` (string).
#[allow(dead_code)]
pub fn create_with_config(config: &serde_json::Value) -> WizardState {
    let mut state = create();

    if let Some(s) = config.get("nickname").and_then(|v| v.as_str()) {
        state.set_field("nickname", FieldValue::Text(s.to_string()));
    }
    if let Some(b) = config.get("public_mining").and_then(|v| v.as_bool()) {
        state.set_field("public_mining", FieldValue::Bool(b));
    }
    if let Some(s) = config.get("payout_address").and_then(|v| v.as_str()) {
        state.set_field("payout_address", FieldValue::Text(s.to_string()));
    }
    if let Some(b) = config.get("ghost_mode").and_then(|v| v.as_bool()) {
        state.set_field("ghost_mode", FieldValue::Bool(b));
    }
    if let Some(b) = config.get("archive_mode").and_then(|v| v.as_bool()) {
        state.set_field("archive_mode", FieldValue::Bool(b));
    }
    if let Some(b) = config.get("bitcoin_pure").and_then(|v| v.as_bool()) {
        state.set_field("bitcoin_pure", FieldValue::Bool(b));
    }
    if let Some(b) = config.get("ghost_pay").and_then(|v| v.as_bool()) {
        state.set_field("ghost_pay", FieldValue::Bool(b));
    }
    if let Some(s) = config.get("mempool_profile").and_then(|v| v.as_str()) {
        let index = match s {
            "permissive" => 0,
            "strict" => 1,
            "custom" => 2,
            _ => 0,
        };
        state.set_field("mempool_profile", FieldValue::Selected(index));
    }

    state
}
