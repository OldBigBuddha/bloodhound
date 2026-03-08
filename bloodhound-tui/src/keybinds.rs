use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{App, Tab};

/// Handle a key event, mutating app state accordingly.
pub fn handle_key(app: &mut App, key: KeyEvent) {
    match key.code {
        // Quit
        KeyCode::Char('q') | KeyCode::Esc => {
            app.should_quit = true;
        }
        // Ctrl-C also quits
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.should_quit = true;
        }

        // Navigation
        KeyCode::Char('j') | KeyCode::Down => app.select_next(),
        KeyCode::Char('k') | KeyCode::Up => app.select_prev(),
        KeyCode::Char('g') => app.jump_top(),
        KeyCode::Char('G') => app.jump_bottom(),

        // Pane switching
        KeyCode::Tab => app.toggle_pane(),

        // Tab switching by number
        KeyCode::Char('1') => app.set_tab(Tab::All),
        KeyCode::Char('2') => app.set_tab(Tab::Exec),
        KeyCode::Char('3') => app.set_tab(Tab::Syscall),
        KeyCode::Char('4') => app.set_tab(Tab::Files),
        KeyCode::Char('5') => app.set_tab(Tab::Network),

        // Tab cycling with 'h'/'l' in detail pane
        KeyCode::Char('l') | KeyCode::Right => {
            if app.active_pane == crate::app::Pane::Detail {
                app.next_tab();
            }
        }
        KeyCode::Char('h') | KeyCode::Left => {
            if app.active_pane == crate::app::Pane::Detail {
                // Previous tab
                let current = app.active_tab.index();
                let prev = if current == 0 {
                    Tab::ALL_TABS.len() - 1
                } else {
                    current - 1
                };
                app.set_tab(Tab::ALL_TABS[prev]);
            }
        }

        _ => {}
    }
}
