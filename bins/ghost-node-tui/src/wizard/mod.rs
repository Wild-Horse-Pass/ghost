//! Generic wizard framework for multi-step configuration flows

use std::collections::HashMap;

pub mod render;

pub mod build_run;
pub mod change_setup;
pub mod ghost_mode;
pub mod haze;
pub mod initial_setup;
pub mod l2_create_lock;
pub mod l2_ghost_id;
pub mod l2_withdraw;
pub mod mempool_policy;
pub mod pool_setup;
pub mod reaper;
pub mod shroud;

/// Field types for wizard forms
#[derive(Debug, Clone)]
pub enum FieldType {
    /// Single-line text input
    Text,
    /// Boolean toggle
    Toggle,
    /// Select from options: Vec of (value, display_label)
    Select(Vec<(&'static str, &'static str)>),
    /// Read-only informational text
    Info(String),
}

/// Field values stored per field key — re-exported from ghost-common for shared use
pub use ghost_common::setup::FieldValue;

/// Definition of a single field in a wizard step
#[derive(Debug, Clone)]
pub struct FieldDef {
    pub key: &'static str,
    pub label: &'static str,
    pub field_type: FieldType,
}

/// Definition of a wizard step (page)
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct WizardStepDef {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub fields: Vec<FieldDef>,
}

/// Wizard completion callback type
#[allow(dead_code)]
pub type WizardSubmitFn = Box<dyn FnOnce(&HashMap<String, FieldValue>) -> String>;

/// State machine for a multi-step wizard
pub struct WizardState {
    /// Unique wizard identifier for dispatch
    pub id: &'static str,
    pub title: String,
    pub steps: Vec<WizardStepDef>,
    pub current_step: usize,
    pub fields: HashMap<String, FieldValue>,
    pub active_field: usize,
    pub error: Option<String>,
    #[allow(dead_code)]
    pub submitting: bool,
    pub complete: bool,
    /// Result message after submission
    pub result_message: Option<String>,
}

impl WizardState {
    /// Create a new wizard with the given id, title, and step definitions
    pub fn new(id: &'static str, title: impl Into<String>, steps: Vec<WizardStepDef>) -> Self {
        let mut fields = HashMap::new();
        // Initialize all fields with defaults
        for step in &steps {
            for field in &step.fields {
                let default = match &field.field_type {
                    FieldType::Text => FieldValue::Text(String::new()),
                    FieldType::Toggle => FieldValue::Bool(false),
                    FieldType::Select(_) => FieldValue::Selected(0),
                    FieldType::Info(_) => FieldValue::Text(String::new()),
                };
                fields.insert(field.key.to_string(), default);
            }
        }

        Self {
            id,
            title: title.into(),
            steps,
            current_step: 0,
            fields,
            active_field: 0,
            error: None,
            submitting: false,
            complete: false,
            result_message: None,
        }
    }

    /// Get the current step definition
    pub fn current_step_def(&self) -> &WizardStepDef {
        &self.steps[self.current_step]
    }

    /// Get the total number of steps
    pub fn total_steps(&self) -> usize {
        self.steps.len()
    }

    /// Check if we're on the first step
    pub fn is_first(&self) -> bool {
        self.current_step == 0
    }

    /// Check if we're on the last step
    pub fn is_last(&self) -> bool {
        self.current_step == self.steps.len() - 1
    }

    /// Get current active field definition (if any editable fields exist)
    pub fn active_field_def(&self) -> Option<&FieldDef> {
        let step = self.current_step_def();
        let editable: Vec<&FieldDef> = step
            .fields
            .iter()
            .filter(|f| !matches!(f.field_type, FieldType::Info(_)))
            .collect();
        editable.get(self.active_field).copied()
    }

    /// Count editable fields in current step
    pub fn editable_field_count(&self) -> usize {
        self.current_step_def()
            .fields
            .iter()
            .filter(|f| !matches!(f.field_type, FieldType::Info(_)))
            .count()
    }

    /// Move to next step, returns true if wizard should submit
    pub fn next_step(&mut self) -> bool {
        self.error = None;
        if self.is_last() {
            return true; // Signal to submit
        }
        self.current_step += 1;
        self.active_field = 0;
        false
    }

    /// Move to previous step
    pub fn prev_step(&mut self) {
        if !self.is_first() {
            self.current_step -= 1;
            self.active_field = 0;
            self.error = None;
        }
    }

    /// Move to next editable field in current step
    pub fn next_field(&mut self) {
        let count = self.editable_field_count();
        if count > 0 {
            self.active_field = (self.active_field + 1) % count;
        }
    }

    /// Move to previous editable field in current step
    pub fn prev_field(&mut self) {
        let count = self.editable_field_count();
        if count > 0 {
            if self.active_field == 0 {
                self.active_field = count - 1;
            } else {
                self.active_field -= 1;
            }
        }
    }

    /// Get the key and field type of the active field (copies data to avoid borrow conflicts)
    fn active_field_info(&self) -> Option<(&'static str, FieldType)> {
        self.active_field_def()
            .map(|f| (f.key, f.field_type.clone()))
    }

    /// Handle a character input for the active text field
    pub fn handle_char(&mut self, c: char) {
        if let Some((key, FieldType::Text)) = self.active_field_info() {
            if let Some(FieldValue::Text(ref mut s)) = self.fields.get_mut(key) {
                s.push(c);
            }
        }
    }

    /// Handle backspace for the active text field
    pub fn handle_backspace(&mut self) {
        if let Some((key, FieldType::Text)) = self.active_field_info() {
            if let Some(FieldValue::Text(ref mut s)) = self.fields.get_mut(key) {
                s.pop();
            }
        }
    }

    /// Toggle the active boolean field
    pub fn handle_toggle(&mut self) {
        let Some((key, field_type)) = self.active_field_info() else {
            return;
        };
        match field_type {
            FieldType::Toggle => {
                if let Some(FieldValue::Bool(ref mut b)) = self.fields.get_mut(key) {
                    *b = !*b;
                }
            }
            FieldType::Select(options) => {
                let len = options.len();
                if let Some(FieldValue::Selected(ref mut i)) = self.fields.get_mut(key) {
                    *i = (*i + 1) % len;
                }
            }
            _ => {}
        }
    }

    /// Move select field up
    pub fn handle_select_up(&mut self) {
        if let Some((key, FieldType::Select(options))) = self.active_field_info() {
            let len = options.len();
            if let Some(FieldValue::Selected(ref mut i)) = self.fields.get_mut(key) {
                if *i > 0 {
                    *i -= 1;
                } else {
                    *i = len - 1;
                }
            }
        }
    }

    /// Move select field down
    pub fn handle_select_down(&mut self) {
        if let Some((key, FieldType::Select(options))) = self.active_field_info() {
            let len = options.len();
            if let Some(FieldValue::Selected(ref mut i)) = self.fields.get_mut(key) {
                *i = (*i + 1) % len;
            }
        }
    }

    /// Set a field value by key
    #[allow(dead_code)]
    pub fn set_field(&mut self, key: &str, value: FieldValue) {
        self.fields.insert(key.to_string(), value);
    }

    /// Get a field value by key
    #[allow(dead_code)]
    pub fn get_field(&self, key: &str) -> Option<&FieldValue> {
        self.fields.get(key)
    }

    /// Handle a key event. Returns WizardAction.
    pub fn handle_key(&mut self, key: crossterm::event::KeyCode) -> WizardAction {
        use crossterm::event::KeyCode;

        if self.complete {
            return WizardAction::Close;
        }

        match key {
            KeyCode::Esc => {
                if self.is_first() {
                    WizardAction::Close
                } else {
                    self.prev_step();
                    WizardAction::Continue
                }
            }
            KeyCode::Enter => {
                if self.next_step() {
                    WizardAction::Submit
                } else {
                    WizardAction::Continue
                }
            }
            KeyCode::Tab => {
                self.next_field();
                WizardAction::Continue
            }
            KeyCode::BackTab => {
                self.prev_field();
                WizardAction::Continue
            }
            KeyCode::Char(' ') => {
                self.handle_toggle();
                WizardAction::Continue
            }
            KeyCode::Up => {
                self.handle_select_up();
                WizardAction::Continue
            }
            KeyCode::Down => {
                self.handle_select_down();
                WizardAction::Continue
            }
            KeyCode::Char(c) => {
                self.handle_char(c);
                WizardAction::Continue
            }
            KeyCode::Backspace => {
                self.handle_backspace();
                WizardAction::Continue
            }
            _ => WizardAction::Continue,
        }
    }
}

/// Actions returned from wizard key handling
#[derive(Debug, PartialEq)]
pub enum WizardAction {
    /// Keep the wizard open, no special action
    Continue,
    /// Wizard requests submission (user pressed Enter on last step)
    Submit,
    /// Wizard requests closure (Esc on first step or after complete)
    Close,
}
