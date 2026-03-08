use crate::correlator::CommandGroup;
use crate::event_model::{BehaviorEvent, EventCategory};

/// Which pane is currently active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    History,
    Output,
    Detail,
}

/// Which tab is active in the detail (bottom-right) pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    All,
    Exec,
    Syscall,
    Files,
    Network,
}

impl Tab {
    pub const ALL_TABS: [Tab; 5] = [Tab::All, Tab::Exec, Tab::Syscall, Tab::Files, Tab::Network];

    pub fn label(&self) -> &'static str {
        match self {
            Tab::All => "All",
            Tab::Exec => "Exec",
            Tab::Syscall => "Syscall",
            Tab::Files => "Files",
            Tab::Network => "Network",
        }
    }

    pub fn index(&self) -> usize {
        match self {
            Tab::All => 0,
            Tab::Exec => 1,
            Tab::Syscall => 2,
            Tab::Files => 3,
            Tab::Network => 4,
        }
    }

    pub fn matches(&self, category: EventCategory) -> bool {
        match self {
            Tab::All => true,
            Tab::Exec => category == EventCategory::Exec,
            Tab::Syscall => category == EventCategory::Syscall,
            Tab::Files => category == EventCategory::Files,
            Tab::Network => category == EventCategory::Network,
        }
    }
}

/// Application state.
pub struct App {
    /// Correlated command groups.
    pub commands: Vec<CommandGroup>,
    /// All events (for lookup by index).
    pub events: Vec<BehaviorEvent>,
    /// Decoded TTY output lines per command group index.
    pub tty_output: Vec<Vec<String>>,

    /// Currently selected command index in the left pane.
    pub selected_command: usize,
    /// Active pane.
    pub active_pane: Pane,
    /// Active detail tab (bottom-right).
    pub active_tab: Tab,
    /// Scroll offset in the output pane (top-right).
    pub output_scroll: usize,
    /// Scroll offset in the detail pane (bottom-right).
    pub detail_scroll: usize,

    /// Source file path.
    pub file_path: String,
    /// Total event count.
    pub total_events: usize,
    /// Whether the app should quit.
    pub should_quit: bool,
}

impl App {
    pub fn new(
        commands: Vec<CommandGroup>,
        events: Vec<BehaviorEvent>,
        tty_output: Vec<Vec<String>>,
        file_path: String,
    ) -> Self {
        let total_events = events.len();
        Self {
            commands,
            events,
            tty_output,
            selected_command: 0,
            active_pane: Pane::History,
            active_tab: Tab::All,
            output_scroll: 0,
            detail_scroll: 0,
            file_path,
            total_events,
            should_quit: false,
        }
    }

    /// Get the currently selected command group.
    pub fn current_group(&self) -> Option<&CommandGroup> {
        self.commands.get(self.selected_command)
    }

    /// Get filtered events for the current command group and active tab.
    pub fn filtered_detail_events(&self) -> Vec<(usize, &BehaviorEvent)> {
        let group = match self.current_group() {
            Some(g) => g,
            None => return vec![],
        };

        group
            .event_indices
            .iter()
            .filter_map(|&idx| self.events.get(idx).map(|e| (idx, e)))
            .filter(|(_, e)| self.active_tab.matches(e.category()))
            .collect()
    }

    // ── Navigation ───────────────────────────────────────────────────────

    pub fn select_next(&mut self) {
        match self.active_pane {
            Pane::History => {
                if !self.commands.is_empty() && self.selected_command < self.commands.len() - 1 {
                    self.selected_command += 1;
                    self.output_scroll = 0;
                    self.detail_scroll = 0;
                }
            }
            Pane::Output => {
                self.output_scroll = self.output_scroll.saturating_add(1);
            }
            Pane::Detail => {
                self.detail_scroll = self.detail_scroll.saturating_add(1);
            }
        }
    }

    pub fn select_prev(&mut self) {
        match self.active_pane {
            Pane::History => {
                if self.selected_command > 0 {
                    self.selected_command -= 1;
                    self.output_scroll = 0;
                    self.detail_scroll = 0;
                }
            }
            Pane::Output => {
                self.output_scroll = self.output_scroll.saturating_sub(1);
            }
            Pane::Detail => {
                self.detail_scroll = self.detail_scroll.saturating_sub(1);
            }
        }
    }

    pub fn jump_top(&mut self) {
        match self.active_pane {
            Pane::History => {
                self.selected_command = 0;
                self.output_scroll = 0;
                self.detail_scroll = 0;
            }
            Pane::Output => {
                self.output_scroll = 0;
            }
            Pane::Detail => {
                self.detail_scroll = 0;
            }
        }
    }

    pub fn jump_bottom(&mut self) {
        match self.active_pane {
            Pane::History => {
                if !self.commands.is_empty() {
                    self.selected_command = self.commands.len() - 1;
                    self.output_scroll = 0;
                    self.detail_scroll = 0;
                }
            }
            Pane::Output => {
                let count = self
                    .tty_output
                    .get(self.selected_command)
                    .map(|v| v.len())
                    .unwrap_or(0);
                self.output_scroll = count.saturating_sub(1);
            }
            Pane::Detail => {
                let count = self.filtered_detail_events().len();
                self.detail_scroll = count.saturating_sub(1);
            }
        }
    }

    pub fn toggle_pane(&mut self) {
        self.active_pane = match self.active_pane {
            Pane::History => Pane::Output,
            Pane::Output => Pane::Detail,
            Pane::Detail => Pane::History,
        };
    }

    pub fn set_tab(&mut self, tab: Tab) {
        self.active_tab = tab;
        self.detail_scroll = 0;
    }

    pub fn next_tab(&mut self) {
        let current = self.active_tab.index();
        let next = (current + 1) % Tab::ALL_TABS.len();
        self.active_tab = Tab::ALL_TABS[next];
        self.detail_scroll = 0;
    }
}
