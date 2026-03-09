use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs, Wrap},
    Frame,
};

use crate::app::{App, HistoryRow, Pane, Tab};
use crate::event_model::EventCategory;

/// Primary color palette.
const HIGHLIGHT_COLOR: Color = Color::Rgb(97, 175, 239);   // Soft blue
const ACTIVE_BORDER: Color = Color::Rgb(97, 175, 239);     // Blue
const INACTIVE_BORDER: Color = Color::Rgb(90, 90, 90);     // Dim gray
const TAB_ACTIVE: Color = Color::Rgb(97, 175, 239);        // Blue
const EXEC_COLOR: Color = Color::Rgb(152, 195, 121);       // Green
const SYSCALL_COLOR: Color = Color::Rgb(198, 120, 221);    // Purple
const FILES_COLOR: Color = Color::Rgb(229, 192, 123);      // Yellow
const NETWORK_COLOR: Color = Color::Rgb(224, 108, 117);    // Red
const DIM_TEXT: Color = Color::Rgb(120, 120, 120);          // Dim
const STATUS_BG: Color = Color::Rgb(40, 44, 52);           // Dark bg
const OUTPUT_COLOR: Color = Color::Rgb(86, 182, 194);      // Cyan
const TREE_COLOR: Color = Color::Rgb(152, 195, 121);       // Green for exec children

/// Render the full UI.
pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),    // Main area
            Constraint::Length(1), // Status bar
        ])
        .split(f.area());

    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(30),
            Constraint::Percentage(70),
        ])
        .split(chunks[0]);

    draw_history_pane(f, app, main_chunks[0]);

    // Split the right side into top (Output) and bottom (Detail)
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(35), // Output (top)
            Constraint::Percentage(65), // Detail tabs (bottom)
        ])
        .split(main_chunks[1]);

    draw_output_pane(f, app, right_chunks[0]);
    draw_detail_pane(f, app, right_chunks[1]);
    draw_status_bar(f, app, chunks[1]);
}

/// Draw the left pane: command history with tree view.
fn draw_history_pane(f: &mut Frame, app: &App, area: Rect) {
    let is_active = app.active_pane == Pane::History;
    let border_color = if is_active { ACTIVE_BORDER } else { INACTIVE_BORDER };

    let title = format!(" History ({} commands) ", app.commands.len());
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let visible = app.visible_rows();

    let items: Vec<ListItem> = visible
        .iter()
        .enumerate()
        .map(|(row_idx, row)| match row {
            HistoryRow::Command(gi) => {
                let group = &app.commands[*gi];
                let has_children = app
                    .exec_trees
                    .get(*gi)
                    .map(|v| !v.is_empty())
                    .unwrap_or(false);
                let is_expanded = app.expanded.get(*gi).copied().unwrap_or(false);

                let arrow = if !has_children {
                    "  "
                } else if is_expanded {
                    "▾ "
                } else {
                    "▸ "
                };

                let cmd_display = if group.command.is_empty() {
                    "(empty)".to_string()
                } else {
                    group.command.clone()
                };
                let event_count = group.event_indices.len();
                let child_count = app.exec_trees.get(*gi).map(|v| v.len()).unwrap_or(0);

                let counter = if child_count > 0 {
                    format!(" ({}/{})", child_count, event_count)
                } else {
                    format!(" ({})", event_count)
                };

                let is_selected = row_idx == app.history_cursor;
                let style = if is_selected {
                    Style::default()
                        .fg(HIGHLIGHT_COLOR)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };

                ListItem::new(Line::from(vec![
                    Span::styled(arrow, style),
                    Span::styled(cmd_display, style),
                    Span::styled(counter, Style::default().fg(DIM_TEXT)),
                ]))
            }
            HistoryRow::Exec { group, child } => {
                let exec_child = &app.exec_trees[*group][*child];

                let indent = "  ".repeat(exec_child.depth);
                let branch = if exec_child.is_last { "└─ " } else { "├─ " };
                let pid_str = format!(" :{}", exec_child.pid);

                let is_selected = row_idx == app.history_cursor;
                let label_style = if is_selected {
                    Style::default()
                        .fg(HIGHLIGHT_COLOR)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(TREE_COLOR)
                };
                let branch_style = if is_selected {
                    Style::default()
                        .fg(HIGHLIGHT_COLOR)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(DIM_TEXT)
                };

                ListItem::new(Line::from(vec![
                    Span::styled(format!("{}{}", indent, branch), branch_style),
                    Span::styled(exec_child.label.clone(), label_style),
                    Span::styled(pid_str, Style::default().fg(DIM_TEXT)),
                ]))
            }
        })
        .collect();

    let mut list_state = ListState::default();
    list_state.select(Some(app.history_cursor));

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(50, 55, 65))
                .add_modifier(Modifier::BOLD),
        );

    f.render_stateful_widget(list, area, &mut list_state);
}

/// Draw the top-right pane: always-visible terminal output.
fn draw_output_pane(f: &mut Frame, app: &App, area: Rect) {
    let is_active = app.active_pane == Pane::Output;
    let border_color = if is_active { ACTIVE_BORDER } else { INACTIVE_BORDER };

    let gi = app.selected_group();
    let lines: Vec<String> = app
        .tty_output
        .get(gi)
        .cloned()
        .unwrap_or_default();

    let title = format!(" Output ({} lines) ", lines.len());
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    if lines.is_empty() {
        let paragraph = Paragraph::new("No terminal output for this command.")
            .style(Style::default().fg(DIM_TEXT))
            .block(block)
            .wrap(Wrap { trim: false });
        f.render_widget(paragraph, area);
    } else {
        let items: Vec<ListItem> = lines
            .iter()
            .map(|line| {
                ListItem::new(Line::from(Span::styled(
                    format!(" {}", line),
                    Style::default().fg(OUTPUT_COLOR),
                )))
            })
            .collect();

        let mut list_state = ListState::default();
        if is_active && !items.is_empty() {
            list_state
                .select(Some(app.output_scroll.min(items.len().saturating_sub(1))));
        }

        let list = List::new(items)
            .block(block)
            .highlight_style(
                Style::default()
                    .bg(Color::Rgb(50, 55, 65))
                    .add_modifier(Modifier::BOLD),
            );

        f.render_stateful_widget(list, area, &mut list_state);
    }
}

/// Draw the bottom-right pane: detail view with tabs.
fn draw_detail_pane(f: &mut Frame, app: &App, area: Rect) {
    let is_active = app.active_pane == Pane::Detail;
    let border_color = if is_active { ACTIVE_BORDER } else { INACTIVE_BORDER };

    // Split into tab bar + content
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Tab bar
            Constraint::Min(1),    // Content
        ])
        .split(area);

    // Tab bar
    let tab_titles: Vec<Line> = Tab::ALL_TABS
        .iter()
        .map(|t| {
            let label = format!("{}:{}", t.index() + 1, t.label());
            let style = if *t == app.active_tab {
                Style::default()
                    .fg(TAB_ACTIVE)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
            } else {
                Style::default().fg(DIM_TEXT)
            };
            Line::from(Span::styled(label, style))
        })
        .collect();

    let tabs = Tabs::new(tab_titles)
        .block(
            Block::default()
                .title(" Events ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .select(app.active_tab.index())
        .highlight_style(Style::default().fg(TAB_ACTIVE));

    f.render_widget(tabs, chunks[0]);

    // Content: filtered events
    let detail_events = app.filtered_detail_events();

    if detail_events.is_empty() {
        let msg = if app.commands.is_empty() {
            "No events loaded."
        } else {
            "No events in this category for the selected command."
        };
        let paragraph = Paragraph::new(msg)
            .style(Style::default().fg(DIM_TEXT))
            .block(
                Block::default()
                    .borders(Borders::LEFT | Borders::RIGHT | Borders::BOTTOM)
                    .border_style(Style::default().fg(border_color)),
            )
            .wrap(Wrap { trim: false });
        f.render_widget(paragraph, chunks[1]);
        return;
    }

    let items: Vec<ListItem> = detail_events
        .iter()
        .map(|(_, event)| {
            let cat = event.category();
            let color = match cat {
                EventCategory::Exec => EXEC_COLOR,
                EventCategory::Syscall => SYSCALL_COLOR,
                EventCategory::Files => FILES_COLOR,
                EventCategory::Network => NETWORK_COLOR,
            };

            let tag = match cat {
                EventCategory::Exec => "EXEC",
                EventCategory::Syscall => "SYS ",
                EventCategory::Files => "FILE",
                EventCategory::Network => "NET ",
            };

            let summary = event.summary_line();
            let line = Line::from(vec![
                Span::styled(
                    format!(" {} ", tag),
                    Style::default()
                        .fg(Color::Black)
                        .bg(color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(summary, Style::default().fg(color)),
            ]);

            ListItem::new(line)
        })
        .collect();

    let mut list_state = ListState::default();
    if is_active && !items.is_empty() {
        list_state.select(Some(app.detail_scroll.min(items.len().saturating_sub(1))));
    }

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::LEFT | Borders::RIGHT | Borders::BOTTOM)
                .border_style(Style::default().fg(border_color)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(50, 55, 65))
                .add_modifier(Modifier::BOLD),
        );

    f.render_stateful_widget(list, chunks[1], &mut list_state);
}

/// Draw the status bar at the bottom.
fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let cmd_info = if app.commands.is_empty() {
        "No commands".to_string()
    } else {
        let gi = app.selected_group();
        format!(
            "Command {}/{}",
            gi + 1,
            app.commands.len()
        )
    };

    let event_count = app
        .current_group()
        .map(|g| g.event_indices.len())
        .unwrap_or(0);

    let pane_name = match app.active_pane {
        Pane::History => "History",
        Pane::Output => "Output",
        Pane::Detail => "Events",
    };

    let line = Line::from(vec![
        Span::styled(
            format!(" {} ", app.file_path),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" │ ", Style::default().fg(DIM_TEXT)),
        Span::styled(
            format!("{} events total", app.total_events),
            Style::default().fg(Color::White),
        ),
        Span::styled(" │ ", Style::default().fg(DIM_TEXT)),
        Span::styled(cmd_info, Style::default().fg(HIGHLIGHT_COLOR)),
        Span::styled(" │ ", Style::default().fg(DIM_TEXT)),
        Span::styled(
            format!("{} events", event_count),
            Style::default().fg(Color::White),
        ),
        Span::styled(" │ ", Style::default().fg(DIM_TEXT)),
        Span::styled(
            format!("▶ {}", pane_name),
            Style::default()
                .fg(HIGHLIGHT_COLOR)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "   j/k:nav  ⏎:expand  Tab:pane  1-5:tab  q:quit ",
            Style::default().fg(DIM_TEXT),
        ),
    ]);

    let paragraph = Paragraph::new(line).style(Style::default().bg(STATUS_BG));
    f.render_widget(paragraph, area);
}
