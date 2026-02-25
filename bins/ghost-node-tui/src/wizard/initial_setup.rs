use super::{FieldDef, FieldType, FieldValue, WizardState, WizardStepDef};

/// Create the initial setup wizard with Max Privacy/Shares defaults (15/15).
///
/// First-run wizard for new node operators. All capabilities default to enabled
/// so operators get maximum shares out of the box. They can disable anything
/// they don't want during the wizard.
pub fn create() -> WizardState {
    let mut wizard = WizardState::new(
        "Initial Node Setup",
        vec![
            WizardStepDef {
                id: "welcome",
                title: "Welcome to Ghost Pool",
                description: "First-run setup for your Ghost Pool node.",
                fields: vec![FieldDef {
                    key: "welcome_info",
                    label: "Welcome",
                    field_type: FieldType::Info(
                        "This wizard configures your node for the Ghost Pool network.\n\n\
                         All capabilities are enabled by default for maximum privacy and \
                         shares (15/15). You can disable anything you don't need.\n\n\
                         Share breakdown:\n\
                         \u{2022} Archive Mode: +5 shares\n\
                         \u{2022} Ghost Pay:    +4 shares\n\
                         \u{2022} Public Mining: +3 shares\n\
                         \u{2022} Reaper:        +2 shares\n\
                         \u{2022} Elder:         +1 share (automatic via MPC)\n\n\
                         Press Enter to continue."
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
                        label: "Enable Public Mining (+3 shares)",
                        field_type: FieldType::Toggle,
                    },
                    FieldDef {
                        key: "payout_address",
                        label: "Payout Address (Bitcoin)",
                        field_type: FieldType::Text,
                    },
                ],
            },
            WizardStepDef {
                id: "capabilities",
                title: "Node Capabilities",
                description: "Enable capabilities to earn shares in the node reward pool.",
                fields: vec![
                    FieldDef {
                        key: "archive_mode",
                        label: "Archive Mode (+5 shares)",
                        field_type: FieldType::Toggle,
                    },
                    FieldDef {
                        key: "ghost_pay",
                        label: "Ghost Pay L2 (+4 shares)",
                        field_type: FieldType::Toggle,
                    },
                    FieldDef {
                        key: "reaper",
                        label: "Enable Reaper (+2 shares)",
                        field_type: FieldType::Toggle,
                    },
                ],
            },
            WizardStepDef {
                id: "privacy",
                title: "Privacy",
                description: "Configure privacy features.",
                fields: vec![
                    FieldDef {
                        key: "ghost_shroud",
                        label: "Ghost Shroud (relay delay)",
                        field_type: FieldType::Toggle,
                    },
                    FieldDef {
                        key: "haze_mode",
                        label: "Ghost Haze (archive stripping)",
                        field_type: FieldType::Select(vec![
                            (
                                "mode_a",
                                "Mode A \u{2014} Hazed (recommended, strips witness/OP_RETURN)",
                            ),
                            (
                                "mode_b",
                                "Mode B \u{2014} Full Archive (stores all data, legal risk)",
                            ),
                        ]),
                    },
                ],
            },
            WizardStepDef {
                id: "profile",
                title: "Mempool Policy",
                description: "Select a mempool acceptance policy.",
                fields: vec![FieldDef {
                    key: "mempool_profile",
                    label: "Mempool Profile",
                    field_type: FieldType::Select(vec![
                        ("permissive", "Permissive \u{2014} Accept all standard"),
                        ("bitcoin_pure", "Bitcoin Pure \u{2014} P2P cash only"),
                        ("full_open", "Full Open \u{2014} Accept everything"),
                    ]),
                }],
            },
            WizardStepDef {
                id: "confirm",
                title: "Confirm",
                description: "Review and apply your configuration.",
                fields: vec![FieldDef {
                    key: "confirm_info",
                    label: "Review",
                    field_type: FieldType::Info(
                        "Review your configuration above.\n\n\
                         Press Enter to apply and start your node.\n\
                         Press Esc to go back and make changes.\n\n\
                         Elder status (+1 share) is assigned automatically when your \
                         node contributes to the MPC ceremony on first startup."
                            .to_string(),
                    ),
                }],
            },
        ],
    );

    // Set max-shares defaults (all capabilities enabled)
    wizard.set_field("public_mining", FieldValue::Bool(true));
    wizard.set_field("archive_mode", FieldValue::Bool(true));
    wizard.set_field("ghost_pay", FieldValue::Bool(true));
    wizard.set_field("ghost_shroud", FieldValue::Bool(true));
    wizard.set_field("reaper", FieldValue::Bool(true));
    // haze_mode defaults to index 0 = "mode_a" (hazed, recommended)
    // mempool_profile defaults to index 0 = "permissive"

    wizard
}
