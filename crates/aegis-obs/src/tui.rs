//! The live dashboard. Rendering is a pure function of [`DashState`] plus a
//! "now" timestamp, so the same code drives live runs (wall clock) and
//! replay (recorded timestamps).

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossterm::event::{self, Event as TermEvent, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, List, ListItem, Paragraph};
use ratatui::Frame;

use crate::event::Event;
use crate::state::{format_ms, DashState};

const GREEN: Color = Color::Green;
const AMBER: Color = Color::Yellow;
const RED: Color = Color::Red;
const DIM: Color = Color::DarkGray;

/// Scroll/follow state for the event-log pane, separate from DashState so
/// replay and live share it.
#[derive(Default)]
pub struct View {
    pub follow: bool,
    pub scroll: usize,
    pub paused: bool,
}

/// Live mode: render `state` (fed by the collector thread) until the run
/// finishes and the user presses a key, or the user quits early.
/// Returns Ok(quit_early).
pub fn run_live(state: Arc<Mutex<DashState>>) -> io::Result<bool> {
    with_terminal(|terminal| {
        let mut view = View {
            follow: true,
            ..Default::default()
        };
        loop {
            let snapshot = state.lock().map(|s| s.clone()).unwrap_or_default();
            let over = snapshot.run_over;
            terminal.draw(|f| draw(f, &snapshot, crate::now_ms(), &view, over))?;
            match poll_key(Duration::from_millis(100))? {
                Some(Key::Quit) => return Ok(!over),
                Some(k) => handle_key(k, &mut view, &snapshot),
                None => {}
            }
        }
    })
}

/// Replay mode: feed recorded events into a fresh DashState, pacing by the
/// gap between recorded timestamps divided by `speed`. `instant` jumps to
/// the final state.
pub fn run_replay(events: Vec<Event>, speed: f64, instant: bool) -> io::Result<()> {
    with_terminal(|terminal| {
        let mut state = DashState::default();
        let mut view = View {
            follow: true,
            ..Default::default()
        };
        let mut queue = events.into_iter().peekable();
        if instant {
            for e in queue.by_ref() {
                state.apply(&e);
            }
        }
        let mut prev_ts: Option<u64> = None;
        let mut wait_ms: u64 = 0;
        loop {
            // advance the stream: apply the next event once its delay elapsed
            if !view.paused {
                while wait_ms == 0 {
                    let Some(e) = queue.next() else { break };
                    let ts = e.ts_ms();
                    state.apply(&e);
                    let gap = prev_ts.map(|p| ts.saturating_sub(p)).unwrap_or(0);
                    prev_ts = Some(ts);
                    wait_ms = (gap as f64 / speed.max(0.01)) as u64;
                }
            }
            let over = state.run_over && queue.peek().is_none();
            terminal.draw(|f| draw(f, &state, state.last_ts_ms, &view, over))?;
            let tick = Duration::from_millis(50.min(wait_ms.max(20)));
            match poll_key(tick)? {
                Some(Key::Quit) => return Ok(()),
                Some(k) => handle_key(k, &mut view, &state),
                None => {}
            }
            if !view.paused {
                wait_ms = wait_ms.saturating_sub(tick.as_millis() as u64);
            }
        }
    })
}

enum Key {
    Quit,
    Pause,
    Follow,
    Up,
    Down,
}

fn poll_key(timeout: Duration) -> io::Result<Option<Key>> {
    if !event::poll(timeout)? {
        return Ok(None);
    }
    if let TermEvent::Key(k) = event::read()? {
        if k.kind != KeyEventKind::Press {
            return Ok(None);
        }
        let key = match k.code {
            KeyCode::Char('q') | KeyCode::Esc => Some(Key::Quit),
            KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => Some(Key::Quit),
            KeyCode::Char('p') | KeyCode::Char(' ') => Some(Key::Pause),
            KeyCode::Char('f') => Some(Key::Follow),
            KeyCode::Char('k') | KeyCode::Up => Some(Key::Up),
            KeyCode::Char('j') | KeyCode::Down => Some(Key::Down),
            _ => None,
        };
        return Ok(key);
    }
    Ok(None)
}

fn handle_key(key: Key, view: &mut View, state: &DashState) {
    match key {
        Key::Quit => {}
        Key::Pause => view.paused = !view.paused,
        Key::Follow => {
            view.follow = true;
            view.scroll = 0;
        }
        Key::Up => {
            view.follow = false;
            view.scroll = (view.scroll + 1).min(state.finished.len().saturating_sub(1));
        }
        Key::Down => {
            if view.scroll > 0 {
                view.scroll -= 1;
            } else {
                view.follow = true;
            }
        }
    }
}

fn with_terminal<T>(
    f: impl FnOnce(&mut ratatui::Terminal<ratatui::backend::CrosstermBackend<io::Stdout>>) -> io::Result<T>,
) -> io::Result<T> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;
    let result = f(&mut terminal);
    // always restore, even on error
    let _ = disable_raw_mode();
    let _ = crossterm::execute!(io::stdout(), LeaveAlternateScreen);
    result
}

/// Pure render: everything below here only reads `state`.
pub fn draw(f: &mut Frame, state: &DashState, now_ms: u64, view: &View, over: bool) {
    let area = f.area();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),                                  // header
            Constraint::Length(worker_panel_height(state)),         // workers + stats
            Constraint::Min(5),                                     // event log
            Constraint::Length(1),                                  // key hints
        ])
        .split(area);
    draw_header(f, rows[0], state, now_ms, over);
    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(rows[1]);
    draw_workers(f, mid[0], state, now_ms);
    draw_stats(f, mid[1], state);
    draw_log(f, rows[2], state, view);
    draw_hints(f, rows[3], view, over);
}

fn worker_panel_height(state: &DashState) -> u16 {
    // borders (2) + one row per worker, capped so the log keeps room
    ((state.workers.len() as u16).clamp(4, 12)) + 2
}

fn draw_header(f: &mut Frame, area: Rect, state: &DashState, now_ms: u64, over: bool) {
    let kind = state.kind.map(|k| k.as_str()).unwrap_or("-");
    let elapsed = if over {
        state.run_duration_ms
    } else {
        now_ms.saturating_sub(state.started_ts_ms)
    };
    let total = if state.total > 0 {
        format!("{}/{}", state.done(), state.total)
    } else {
        format!("{}", state.done())
    };
    let cache = state
        .cache_ratio()
        .map(|r| format!("{:.0}%", r * 100.0))
        .unwrap_or_else(|| "--".into());
    let status = if over {
        Span::styled(
            if state.failed == 0 { " COMPLETE " } else { " FAILURES " },
            Style::default()
                .fg(Color::Black)
                .bg(if state.failed == 0 { GREEN } else { RED })
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(" LIVE ", Style::default().fg(Color::Black).bg(AMBER))
    };
    let line = Line::from(vec![
        Span::styled(" AEGIS ", Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
        Span::styled("▓ ", Style::default().fg(DIM)),
        Span::styled(state.run_id.clone(), Style::default().fg(AMBER)),
        Span::styled(format!(" ▓ {kind} "), Style::default().fg(DIM)),
        status,
        Span::raw(format!(
            "  elapsed {}  pkgs {}  {:.1} pkg/s  cache {}",
            format_ms(elapsed),
            total,
            state.throughput(now_ms),
            cache
        )),
    ]);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(GREEN));
    f.render_widget(Paragraph::new(line).block(block), area);
}

fn draw_workers(f: &mut Frame, area: Rect, state: &DashState, now_ms: u64) {
    let items: Vec<ListItem> = state
        .workers
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let line = match &w.current {
                Some((pkg, since)) => Line::from(vec![
                    Span::styled(format!(" w{i:<2} "), Style::default().fg(DIM)),
                    Span::styled("▶ ", Style::default().fg(AMBER)),
                    Span::styled(pkg.clone(), Style::default().fg(Color::White)),
                    Span::styled(
                        format!("  {}", format_ms(now_ms.saturating_sub(*since))),
                        Style::default().fg(AMBER),
                    ),
                ]),
                None => Line::from(vec![
                    Span::styled(format!(" w{i:<2} "), Style::default().fg(DIM)),
                    Span::styled("∙ idle", Style::default().fg(DIM)),
                    Span::styled(format!("  ({} done)", w.done), Style::default().fg(DIM)),
                ]),
            };
            ListItem::new(line)
        })
        .collect();
    let block = Block::default()
        .title(Span::styled(" WORKERS ", Style::default().fg(GREEN)))
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(DIM));
    f.render_widget(List::new(items).block(block), area);
}

fn draw_stats(f: &mut Frame, area: Rect, state: &DashState) {
    let mut lines: Vec<Line> = Vec::new();
    let pending = state.total.saturating_sub(state.done());
    lines.push(Line::from(vec![
        Span::styled(" pass ", Style::default().fg(GREEN)),
        Span::raw(format!("{}", state.passed)),
        Span::styled("  fail ", Style::default().fg(RED)),
        Span::raw(format!("{}", state.failed)),
        Span::styled("  pending ", Style::default().fg(DIM)),
        Span::raw(format!("{pending}")),
    ]));
    if let Some((p50, p95)) = state.percentiles() {
        lines.push(Line::from(vec![
            Span::styled(" p50 ", Style::default().fg(DIM)),
            Span::raw(format_ms(p50)),
            Span::styled("  p95 ", Style::default().fg(DIM)),
            Span::raw(format_ms(p95)),
        ]));
    }
    if !state.finished.is_empty() {
        lines.push(Line::from(Span::styled(
            " slowest:",
            Style::default().fg(DIM),
        )));
        for p in state.slowest(5) {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(format_ms(p.duration_ms), Style::default().fg(AMBER)),
                Span::raw(format!("  {}", p.label)),
            ]));
        }
    }
    let block = Block::default()
        .title(Span::styled(" STATS ", Style::default().fg(GREEN)))
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(DIM));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_log(f: &mut Frame, area: Rect, state: &DashState, view: &View) {
    let capacity = area.height.saturating_sub(2) as usize;
    let n = state.finished.len();
    // follow = pinned to newest; scroll counts lines back from the end
    let end = if view.follow {
        n
    } else {
        n.saturating_sub(view.scroll)
    };
    let start = end.saturating_sub(capacity);
    let items: Vec<ListItem> = state.finished[start..end]
        .iter()
        .map(|p| {
            let (mark, color) = if p.passed {
                ("✓", GREEN)
            } else {
                ("✗", RED)
            };
            let mut spans = vec![
                Span::styled(format!(" {mark} "), Style::default().fg(color)),
                Span::styled(
                    format!("{:<40}", truncate(&p.label, 40)),
                    Style::default().fg(if p.passed { Color::White } else { RED }),
                ),
                Span::styled(format!(" {:>7}", format_ms(p.duration_ms)), Style::default().fg(AMBER)),
                Span::raw(format!("  score {:>5.2}  ", p.score)),
                Span::styled(
                    p.verdict.clone(),
                    Style::default().fg(if p.passed { DIM } else { RED }),
                ),
            ];
            if let Some(d) = &p.detail {
                spans.push(Span::styled(
                    format!("  {}", truncate(d.lines().next().unwrap_or(""), 60)),
                    Style::default().fg(DIM),
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    let title = if view.follow {
        " EVENT LOG ".to_string()
    } else {
        format!(" EVENT LOG (scrolled -{}) ", view.scroll)
    };
    let block = Block::default()
        .title(Span::styled(title, Style::default().fg(GREEN)))
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(DIM));
    f.render_widget(List::new(items).block(block), area);
}

fn draw_hints(f: &mut Frame, area: Rect, view: &View, over: bool) {
    let mut hint = String::from(" q quit  j/k scroll  f follow");
    if view.paused {
        hint.push_str("  p resume [PAUSED]");
    } else {
        hint.push_str("  p pause");
    }
    if over {
        hint.push_str("  — run finished, q to exit");
    }
    f.render_widget(
        Paragraph::new(Span::styled(hint, Style::default().fg(DIM))),
        area,
    );
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let cut: String = s.chars().take(n.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{RunKind, SCHEMA_VERSION};
    use ratatui::backend::TestBackend;

    fn sample_state() -> DashState {
        let mut s = DashState::default();
        s.apply(&Event::RunStarted {
            v: SCHEMA_VERSION,
            ts_ms: 1000,
            run_id: "ci-20260806-120000".into(),
            kind: RunKind::Ci,
            total: 3,
            workers: 2,
            meta: Default::default(),
        });
        s.apply(&Event::PackageStarted {
            ts_ms: 1100,
            worker: 0,
            pkg: "lodash".into(),
            version: "4.17.21".into(),
            eco: "npm".into(),
        });
        s.apply(&Event::PackageFinished {
            ts_ms: 1500,
            worker: 1,
            pkg: "evil-pkg".into(),
            version: "1.0.0".into(),
            eco: "npm".into(),
            duration_ms: 400,
            verdict: "block".into(),
            score: 0.91,
            passed: false,
            cache_hits: 1,
            cache_misses: 1,
            bytes: 0,
            files: 3,
            detail: Some("shell-spawn".into()),
        });
        s
    }

    #[test]
    fn draw_renders_key_content() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        let state = sample_state();
        let view = View {
            follow: true,
            ..Default::default()
        };
        terminal
            .draw(|f| draw(f, &state, 2000, &view, false))
            .unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        for needle in [
            "AEGIS",
            "ci-20260806-120000",
            "lodash@4.17.21",
            "evil-pkg",
            "WORKERS",
            "STATS",
            "EVENT LOG",
            "LIVE",
        ] {
            assert!(text.contains(needle), "missing {needle}");
        }
    }

    #[test]
    fn draw_finished_banner() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        let mut state = sample_state();
        state.apply(&Event::RunFinished {
            ts_ms: 3000,
            duration_ms: 2000,
            passed: 2,
            failed: 1,
            cache_hits: 0,
            cache_misses: 0,
        });
        let view = View::default();
        terminal
            .draw(|f| draw(f, &state, 3000, &view, true))
            .unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(text.contains("FAILURES"));
        assert!(text.contains("run finished"));
    }
}
