use chrono::{DateTime, FixedOffset, Utc};

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

// ── Tree data structures ─────────────────────────────────────────────────────

/// A child execve entry in the process tree under a command.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ExecChild {
    /// Display label (e.g., "curl -sL https://...").
    pub label: String,
    /// Process ID.
    pub pid: u32,
    /// Tree depth (1 = direct child of shell, 2 = grandchild, etc.).
    pub depth: usize,
    /// Index into the global events array.
    pub event_index: usize,
    /// Whether this is the last sibling at its depth level.
    pub is_last: bool,
}

/// A row in the visible history pane (commands + expanded exec children).
#[derive(Debug, Clone)]
pub enum HistoryRow {
    /// A command entry (index into commands[]).
    Command(usize),
    /// An exec child (group index, child index within exec_trees[group]).
    Exec { group: usize, child: usize },
}

/// Application state.
pub struct App {
    /// Correlated command groups.
    pub commands: Vec<CommandGroup>,
    /// All events (for lookup by index).
    pub events: Vec<BehaviorEvent>,
    /// Decoded TTY output lines per command group index.
    pub tty_output: Vec<Vec<String>>,
    /// Exec child trees per command group (parallel to commands).
    pub exec_trees: Vec<Vec<ExecChild>>,
    /// Expand/collapse state per command group (parallel to commands).
    pub expanded: Vec<bool>,

    /// Currently selected row in the visible history list.
    pub history_cursor: usize,
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

    /// Absolute boot time (UTC) for converting monotonic timestamps to wall clock.
    pub boot_time_utc: DateTime<Utc>,
    /// Timezone offset for display.
    pub tz_offset: FixedOffset,
}

impl App {
    pub fn new(
        commands: Vec<CommandGroup>,
        events: Vec<BehaviorEvent>,
        tty_output: Vec<Vec<String>>,
        exec_trees: Vec<Vec<ExecChild>>,
        file_path: String,
        boot_time_utc: DateTime<Utc>,
        tz_offset: FixedOffset,
    ) -> Self {
        let total_events = events.len();
        let expanded = vec![false; commands.len()];
        Self {
            commands,
            events,
            tty_output,
            exec_trees,
            expanded,
            history_cursor: 0,
            active_pane: Pane::History,
            active_tab: Tab::All,
            output_scroll: 0,
            detail_scroll: 0,
            file_path,
            total_events,
            should_quit: false,
            boot_time_utc,
            tz_offset,
        }
    }

    /// Convert a monotonic eBPF timestamp to a display string in the configured timezone.
    pub fn format_timestamp(&self, mono_secs: f64) -> String {
        let wall_utc = self.boot_time_utc
            + chrono::Duration::milliseconds((mono_secs * 1000.0) as i64);
        let wall_local = wall_utc.with_timezone(&self.tz_offset);
        wall_local.format("%H:%M:%S").to_string()
    }

    /// Compute the flat list of visible rows (commands + expanded children).
    pub fn visible_rows(&self) -> Vec<HistoryRow> {
        let mut rows = Vec::new();
        for (gi, _) in self.commands.iter().enumerate() {
            rows.push(HistoryRow::Command(gi));
            if self.expanded.get(gi).copied().unwrap_or(false) {
                if let Some(children) = self.exec_trees.get(gi) {
                    for (ci, _) in children.iter().enumerate() {
                        rows.push(HistoryRow::Exec { group: gi, child: ci });
                    }
                }
            }
        }
        rows
    }

    /// Get the group index for the currently selected history row.
    pub fn selected_group(&self) -> usize {
        let rows = self.visible_rows();
        match rows.get(self.history_cursor) {
            Some(HistoryRow::Command(gi)) => *gi,
            Some(HistoryRow::Exec { group, .. }) => *group,
            None => 0,
        }
    }

    /// Get the currently selected command group.
    pub fn current_group(&self) -> Option<&CommandGroup> {
        self.commands.get(self.selected_group())
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

    /// Toggle expand/collapse on the current row.
    pub fn toggle_expand(&mut self) {
        let rows = self.visible_rows();
        match rows.get(self.history_cursor).cloned() {
            Some(HistoryRow::Command(gi)) => {
                let has_children = self
                    .exec_trees
                    .get(gi)
                    .map(|v| !v.is_empty())
                    .unwrap_or(false);
                if has_children {
                    if let Some(exp) = self.expanded.get_mut(gi) {
                        *exp = !*exp;
                    }
                }
            }
            Some(HistoryRow::Exec { group, .. }) => {
                // Collapse the parent and move cursor to it
                if let Some(exp) = self.expanded.get_mut(group) {
                    *exp = false;
                }
                let rows = self.visible_rows();
                for (i, row) in rows.iter().enumerate() {
                    if matches!(row, HistoryRow::Command(g) if *g == group) {
                        self.history_cursor = i;
                        break;
                    }
                }
            }
            None => {}
        }
    }

    // ── Navigation ───────────────────────────────────────────────────────

    pub fn select_next(&mut self) {
        match self.active_pane {
            Pane::History => {
                let count = self.visible_rows().len();
                if count > 0 && self.history_cursor < count - 1 {
                    self.history_cursor += 1;
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
                if self.history_cursor > 0 {
                    self.history_cursor -= 1;
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
                self.history_cursor = 0;
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
                let count = self.visible_rows().len();
                if count > 0 {
                    self.history_cursor = count - 1;
                }
                self.output_scroll = 0;
                self.detail_scroll = 0;
            }
            Pane::Output => {
                let gi = self.selected_group();
                let count = self
                    .tty_output
                    .get(gi)
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
