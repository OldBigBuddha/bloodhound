//! Render-level regression tests — the "does the TUI still draw the right
//! thing" layer.
//!
//! These snapshot the output of [`ui::draw`] against a fixed-size
//! [`TestBackend`] for each fixture + state combination. They guard against
//! the #19 failure mode: daemon-correct and logic-correct, but the TUI's
//! consumption of the daemon output was stale. Unit tests (exec-tree logic,
//! correlator filtering, dedup) can't see that class of bug because they
//! don't exercise `ui::draw`.
//!
//! Test fixtures live in `bloodhound-tui/testdata/` and are shared with the
//! daemon's e2e suite. When fixtures are regenerated (daemon output shape
//! changes), snapshots here need `cargo insta review`.

use std::path::PathBuf;

use chrono::{DateTime, FixedOffset, TimeZone, Utc};
use ratatui::{backend::TestBackend, Terminal};

use crate::app::{App, Tab};
use crate::ui;

// ── Test helpers ─────────────────────────────────────────────────────────────

fn fixture_path(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("testdata");
    p.push(name);
    p
}

/// Fixed wall-clock anchor for deterministic timestamp rendering.
///
/// Production `main()` derives this from the fixture's file mtime, which
/// varies per checkout and would churn snapshots on every `git clone`.
fn pinned_boot_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()
}

fn utc_offset() -> FixedOffset {
    FixedOffset::east_opt(0).unwrap()
}

fn load_app(fixture: &str) -> App {
    crate::build_app_from_path(&fixture_path(fixture), utc_offset(), Some(pinned_boot_time()))
        .expect("fixture should parse cleanly")
}

fn render(app: &App) -> String {
    render_sized(app, 140, 40)
}

fn render_sized(app: &App, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("TestBackend terminal");
    terminal.draw(|f| ui::draw(f, app)).expect("draw");
    format!("{}", terminal.backend())
}

// ── Scenarios enumerated in issue #20 ────────────────────────────────────────

/// Scenario 1: default render against the file-exploration fixture.
///
/// Guards overall layout, the `History (N commands)` title, per-command
/// `(seen/total)` event-count formatting, and pre-session bucket rendering.
#[test]
fn initial_render_file_exploration() {
    let app = load_app("01_file_exploration.ndjson");
    insta::assert_snapshot!(render(&app));
}

/// Scenario 2: exec-tree expansion on a forking command.
///
/// Relies on the `start_time_ns` pid-reuse disambiguation merged in #19 —
/// if two processes reuse the same pid within one command, they must stay
/// distinct rows in the tree.
#[test]
fn exec_tree_expanded_process_lifecycle() {
    let mut app = load_app("03_process_lifecycle.ndjson");

    let gi = app
        .exec_trees
        .iter()
        .position(|t| !t.is_empty())
        .expect("process_lifecycle fixture should contain at least one forking command");
    app.history_cursor = gi;
    app.toggle_expand();

    insta::assert_snapshot!(render(&app));
}

/// Scenario 3: synthetic LIFECYCLE/HEARTBEAT events must not leak into
/// per-command correlation.
///
/// The correlator strips these event types from `CommandGroup::event_indices`
/// at construction time; nothing the TUI draws should mention them by name.
/// Substring assertions (instead of a snapshot) make the failure mode
/// legible — a snapshot diff alone wouldn't communicate "this string must
/// never appear."
#[test]
fn detail_pane_excludes_lifecycle_and_heartbeat() {
    let mut app = load_app("03_process_lifecycle.ndjson");

    // Sanity: the fixture must actually contain lifecycle events at the
    // raw layer, otherwise this test is tautologically true.
    let has_lifecycle = app
        .events
        .iter()
        .any(|e| e.event.event_type == "LIFECYCLE");
    assert!(
        has_lifecycle,
        "03_process_lifecycle.ndjson should contain LIFECYCLE events",
    );

    // Sweep the first 5 commands across every tab. LIFECYCLE/HEARTBEAT
    // are stripped globally, so one command would suffice — a small
    // sweep catches edge cases like commands whose window happens to
    // coincide with a heartbeat.
    for gi in 0..app.commands.len().min(5) {
        app.history_cursor = gi;
        for &tab in &Tab::ALL_TABS {
            app.set_tab(tab);
            let rendered = render(&app);
            assert!(
                !rendered.contains("LIFECYCLE"),
                "command #{gi} tab={:?}: 'LIFECYCLE' leaked into the TUI",
                tab,
            );
            assert!(
                !rendered.contains("HEARTBEAT"),
                "command #{gi} tab={:?}: 'HEARTBEAT' leaked into the TUI",
                tab,
            );
        }
    }
}

/// Scenario 4: active-pane highlight moves when `Tab` is pressed.
///
/// Three snapshots (one per pane) so a border-style regression is
/// visible in a single insta review.
#[test]
fn active_pane_highlight_moves_on_tab() {
    let mut app = load_app("01_file_exploration.ndjson");

    insta::assert_snapshot!("pane_history_active", render(&app));
    app.toggle_pane();
    insta::assert_snapshot!("pane_output_active", render(&app));
    app.toggle_pane();
    insta::assert_snapshot!("pane_detail_active", render(&app));
}

/// Scenario 5: detail-pane filtering under each tab.
///
/// One snapshot per tab. A regression in `Tab::matches` or the
/// `filtered_detail_events` pipeline produces a visible diff.
#[test]
fn tab_switching_filters_detail_pane() {
    let mut app = load_app("01_file_exploration.ndjson");

    for &tab in &Tab::ALL_TABS {
        app.set_tab(tab);
        let name = format!("tab_{}", tab.label().to_lowercase());
        insta::assert_snapshot!(name, render(&app));
    }
}
