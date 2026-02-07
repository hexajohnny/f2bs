use std::collections::HashSet;
use std::io;
use std::net::IpAddr;
use std::process::Command;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyModifiers,
    MouseEvent, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Terminal;

#[derive(Debug, Clone)]
struct JailStatus {
    name: String,
    ips: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Jails,
    Ips,
}

impl Default for Focus {
    fn default() -> Self {
        Self::Jails
    }
}

#[derive(Debug, Default)]
struct UiState {
    jails: Vec<JailStatus>,
    jail_state: ListState,
    ip_state: ListState,
    focus: Focus,
    status: String,
    confirm_unban: Option<String>,
    jail_rect: Option<Rect>,
    ip_rect: Option<Rect>,
    modal_yes_rect: Option<Rect>,
    modal_no_rect: Option<Rect>,
}

impl UiState {
    fn new() -> Self {
        let mut state = Self::default();
        state.focus = Focus::Jails;
        state
    }

    fn selected_jail_index(&self) -> usize {
        self.jail_state.selected().unwrap_or(0)
    }

    fn selected_ip_index(&self) -> usize {
        self.ip_state.selected().unwrap_or(0)
    }

    fn selected_jail(&self) -> Option<&JailStatus> {
        self.jails.get(self.selected_jail_index())
    }

    fn selected_ip(&self) -> Option<&str> {
        self.selected_jail()
            .and_then(|jail| jail.ips.get(self.selected_ip_index()))
            .map(|s| s.as_str())
    }

    fn set_status<S: Into<String>>(&mut self, msg: S) {
        self.status = msg.into();
    }

    fn refresh(&mut self) {
        match fetch_status() {
            Ok(jails) => {
                self.jails = jails;
                if self.jails.is_empty() {
                    self.jail_state.select(None);
                    self.ip_state.select(None);
                    self.set_status("No jails reported by fail2ban-client");
                } else {
                    self.jail_state.select(Some(0));
                    self.ip_state.select(Some(0));
                    self.set_status("Refreshed");
                }
            }
            Err(err) => {
                self.set_status(format!("Refresh failed: {err}"));
            }
        }
    }

    fn move_jail(&mut self, delta: i32) {
        if self.jails.is_empty() {
            return;
        }
        let len = self.jails.len() as i32;
        let current = self.jail_state.selected().unwrap_or(0) as i32;
        let next = (current + delta).clamp(0, len.saturating_sub(1));
        self.jail_state.select(Some(next as usize));
        self.ip_state.select(Some(0));
    }

    fn move_ip(&mut self, delta: i32) {
        let Some(jail) = self.selected_jail() else {
            return;
        };
        if jail.ips.is_empty() {
            return;
        }
        let len = jail.ips.len() as i32;
        let current = self.ip_state.selected().unwrap_or(0) as i32;
        let next = (current + delta).clamp(0, len.saturating_sub(1));
        self.ip_state.select(Some(next as usize));
    }
}

fn run_fail2ban(args: &[&str]) -> Result<String> {
    let output = Command::new("fail2ban-client")
        .args(args)
        .output()
        .with_context(|| "failed to execute fail2ban-client")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let msg = if !stderr.is_empty() { stderr } else { stdout };
        return Err(anyhow!(msg));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn parse_jail_list(output: &str) -> Vec<String> {
    for line in output.lines() {
        if let Some((_, tail)) = line.split_once("Jail list:") {
            let tail = tail.trim();
            if tail.is_empty() {
                return Vec::new();
            }
            return tail
                .split(',')
                .map(|j| j.trim())
                .filter(|j| !j.is_empty())
                .map(String::from)
                .collect();
        }
    }
    Vec::new()
}

fn extract_ips(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut ips = Vec::new();
    for token in text.replace(',', " ").split_whitespace() {
        if token.is_empty() {
            continue;
        }
        if token.parse::<IpAddr>().is_ok() && seen.insert(token.to_string()) {
            ips.push(token.to_string());
        }
    }
    ips
}

fn parse_banned_ips(output: &str) -> Vec<String> {
    if let Some(idx) = output.find("Banned IP list:") {
        let tail = &output[idx + "Banned IP list:".len()..];
        return extract_ips(tail);
    }
    Vec::new()
}

fn fetch_status() -> Result<Vec<JailStatus>> {
    let status = run_fail2ban(&["status"])?;
    let jails = parse_jail_list(&status);
    let mut results = Vec::new();
    for jail in jails {
        let jail_status = run_fail2ban(&["status", &jail])?;
        let ips = parse_banned_ips(&jail_status);
        results.push(JailStatus { name: jail, ips });
    }
    Ok(results)
}

fn draw_ui(frame: &mut ratatui::Frame, state: &mut UiState) {
    let size = frame.area();
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(size);

    let header = render_header(state);
    frame.render_widget(header, layout[0]);

    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(layout[1]);

    state.jail_rect = Some(body_chunks[0]);
    state.ip_rect = Some(body_chunks[1]);
    render_jails(frame, body_chunks[0], state);
    render_ips(frame, body_chunks[1], state);

    let footer = render_footer(state);
    frame.render_widget(footer, layout[2]);

    if let Some(ip) = state.confirm_unban.clone() {
        render_modal(frame, size, &ip, state);
    } else {
        state.modal_yes_rect = None;
        state.modal_no_rect = None;
    }
}

fn render_header(state: &UiState) -> Paragraph<'_> {
    let accent = Style::default().fg(Color::Rgb(255, 184, 108)).add_modifier(Modifier::BOLD);
    let calm = Style::default().fg(Color::Rgb(120, 200, 210));
    let text = vec![
        Line::from(vec![
            Span::styled("Fail2Ban Sentinel", accent),
            Span::raw("  "),
            Span::styled("live jail scanner & remover", calm),
        ]),
        Line::from(vec![
            Span::styled(
                format!(
                    "Jails: {}  Total Banned: {}",
                    state.jails.len(),
                    total_banned(state)
                ),
                Style::default().fg(Color::Rgb(190, 190, 190)),
            ),
        ]),
    ];

    Paragraph::new(Text::from(text))
        .alignment(Alignment::Left)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(Color::Rgb(80, 80, 80))),
        )
}

fn render_jails(frame: &mut ratatui::Frame, area: Rect, state: &mut UiState) {
    let items: Vec<ListItem> = if state.jails.is_empty() {
        vec![ListItem::new("No jails found")]
    } else {
        state
            .jails
            .iter()
            .map(|jail| {
                let count = jail.ips.len();
                let label = format!("{}  [{}]", jail.name, count);
                ListItem::new(label)
            })
            .collect()
    };

    let block = Block::default()
        .title("Jails")
        .borders(Borders::ALL)
        .border_style(border_style(state.focus == Focus::Jails));

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(255, 184, 108))
                .fg(Color::Rgb(20, 20, 20))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    frame.render_stateful_widget(list, area, &mut state.jail_state);
}

fn render_ips(frame: &mut ratatui::Frame, area: Rect, state: &mut UiState) {
    let mut items: Vec<ListItem> = Vec::new();
    if let Some(jail) = state.selected_jail() {
        if jail.ips.is_empty() {
            items.push(ListItem::new("No banned IPs"));
        } else {
            for ip in &jail.ips {
                items.push(ListItem::new(ip.clone()));
            }
        }
    } else {
        items.push(ListItem::new("Select a jail"));
    }

    let title = if let Some(jail) = state.selected_jail() {
        format!("Banned IPs - {}", jail.name)
    } else {
        "Banned IPs".to_string()
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style(state.focus == Focus::Ips));

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(88, 196, 220))
                .fg(Color::Rgb(10, 10, 10))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    frame.render_stateful_widget(list, area, &mut state.ip_state);
}

fn render_footer(state: &UiState) -> Paragraph<'_> {
    let help = Line::from(vec![
        Span::styled("q", Style::default().fg(Color::Rgb(255, 184, 108)).add_modifier(Modifier::BOLD)),
        Span::raw(" quit  "),
        Span::styled("r", Style::default().fg(Color::Rgb(255, 184, 108)).add_modifier(Modifier::BOLD)),
        Span::raw(" refresh  "),
        Span::styled("tab", Style::default().fg(Color::Rgb(255, 184, 108)).add_modifier(Modifier::BOLD)),
        Span::raw(" switch panel  "),
        Span::styled("enter", Style::default().fg(Color::Rgb(255, 184, 108)).add_modifier(Modifier::BOLD)),
        Span::raw(" unban"),
    ]);

    let status = Line::from(Span::styled(
        state.status.clone(),
        Style::default().fg(Color::Rgb(180, 180, 180)),
    ));

    Paragraph::new(Text::from(vec![help, status]))
        .block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(Color::Rgb(80, 80, 80))),
        )
        .wrap(Wrap { trim: true })
}

fn render_modal(frame: &mut ratatui::Frame, area: Rect, ip: &str, state: &mut UiState) {
    let modal_area = centered_rect(60, 30, area);
    frame.render_widget(Clear, modal_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title("Action")
        .border_style(Style::default().fg(Color::Rgb(255, 184, 108)));

    frame.render_widget(block, modal_area);

    let inner = Rect {
        x: modal_area.x + 1,
        y: modal_area.y + 1,
        width: modal_area.width.saturating_sub(2),
        height: modal_area.height.saturating_sub(2),
    };

    let content_area = Rect {
        x: inner.x,
        y: inner.y,
        width: inner.width,
        height: inner.height.saturating_sub(2),
    };

    let button_row = Rect {
        x: inner.x,
        y: inner.y + inner.height.saturating_sub(1),
        width: inner.width,
        height: 1,
    };

    let lines = vec![
        Line::from(Span::styled(
            "Confirm Unban",
            Style::default().fg(Color::Rgb(255, 184, 108)).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::raw("")),
        Line::from(Span::raw(format!("Unban {ip}?"))),
        Line::from(Span::raw("")),
        Line::from(Span::raw("Press y/n or click a button")),
    ];

    let paragraph = Paragraph::new(Text::from(lines))
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, content_area);

    let button_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(button_row);

    let yes_style = Style::default()
        .bg(Color::Rgb(255, 184, 108))
        .fg(Color::Rgb(20, 20, 20))
        .add_modifier(Modifier::BOLD);
    let no_style = Style::default()
        .bg(Color::Rgb(88, 196, 220))
        .fg(Color::Rgb(10, 10, 10))
        .add_modifier(Modifier::BOLD);

    let yes = Paragraph::new("Confirm").style(yes_style).alignment(Alignment::Center);
    let no = Paragraph::new("Cancel").style(no_style).alignment(Alignment::Center);

    frame.render_widget(yes, button_chunks[0]);
    frame.render_widget(no, button_chunks[1]);

    state.modal_yes_rect = Some(button_chunks[0]);
    state.modal_no_rect = Some(button_chunks[1]);
}

fn border_style(active: bool) -> Style {
    if active {
        Style::default().fg(Color::Rgb(255, 184, 108))
    } else {
        Style::default().fg(Color::Rgb(80, 80, 80))
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn total_banned(state: &UiState) -> usize {
    state.jails.iter().map(|j| j.ips.len()).sum()
}

fn main() -> Result<()> {
    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).context("enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("init terminal")?;

    let res = run_app(&mut terminal);

    disable_raw_mode().ok();
    execute!(
        terminal.backend_mut(),
        DisableMouseCapture,
        LeaveAlternateScreen
    )
    .ok();
    terminal.show_cursor().ok();

    res
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    let mut state = UiState::new();
    state.refresh();

    loop {
        terminal.draw(|frame| draw_ui(frame, &mut state))?;

        if event::poll(Duration::from_millis(200))? {
            match event::read()? {
                Event::Key(key) => {
                    if handle_key(key, &mut state)? {
                        break;
                    }
                }
                Event::Mouse(mouse) => {
                    if handle_mouse(mouse, &mut state)? {
                        break;
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

fn handle_key(key: KeyEvent, state: &mut UiState) -> Result<bool> {
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return Ok(true);
    }

    if let Some(ip) = state.confirm_unban.clone() {
        return handle_modal_key(key, state, ip);
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Char('Q') => return Ok(true),
        KeyCode::Char('r') | KeyCode::Char('R') => state.refresh(),
        KeyCode::Tab => {
            state.focus = if state.focus == Focus::Jails {
                Focus::Ips
            } else {
                Focus::Jails
            }
        }
        KeyCode::Up | KeyCode::Char('k') => match state.focus {
            Focus::Jails => state.move_jail(-1),
            Focus::Ips => state.move_ip(-1),
        },
        KeyCode::Down | KeyCode::Char('j') => match state.focus {
            Focus::Jails => state.move_jail(1),
            Focus::Ips => state.move_ip(1),
        },
        KeyCode::Enter => {
            if state.focus == Focus::Jails {
                state.focus = Focus::Ips;
            } else if let Some(ip) = state.selected_ip() {
                state.confirm_unban = Some(ip.to_string());
            }
        }
        KeyCode::Char('u') | KeyCode::Char('U') => {
            if let Some(ip) = state.selected_ip() {
                state.confirm_unban = Some(ip.to_string());
            }
        }
        _ => {}
    }

    Ok(false)
}

fn handle_modal_key(key: KeyEvent, state: &mut UiState, ip: String) -> Result<bool> {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
            match run_fail2ban(&["unban", &ip]) {
                Ok(_) => {
                    state.set_status(format!("Unbanned {ip}"));
                    state.confirm_unban = None;
                    state.refresh();
                }
                Err(err) => {
                    state.set_status(format!("Unban failed for {ip}: {err}"));
                    state.confirm_unban = None;
                }
            }
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            state.confirm_unban = None;
            state.set_status("Unban canceled");
        }
        _ => {}
    }

    Ok(false)
}

fn handle_mouse(mouse: MouseEvent, state: &mut UiState) -> Result<bool> {
    if mouse.kind != MouseEventKind::Down(crossterm::event::MouseButton::Left) {
        return Ok(false);
    }

    if let Some(ip) = state.confirm_unban.clone() {
        if let Some(rect) = state.modal_yes_rect {
            if point_in_rect(mouse.column, mouse.row, rect) {
                return handle_modal_key(
                    KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
                    state,
                    ip,
                );
            }
        }
        if let Some(rect) = state.modal_no_rect {
            if point_in_rect(mouse.column, mouse.row, rect) {
                return handle_modal_key(
                    KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()),
                    state,
                    ip,
                );
            }
        }
        return Ok(false);
    }

    if let Some(rect) = state.jail_rect {
        if let Some(index) = list_index_from_mouse(mouse.column, mouse.row, rect, state.jails.len()) {
            state.focus = Focus::Jails;
            state.jail_state.select(Some(index));
            state.ip_state.select(Some(0));
            return Ok(false);
        }
    }

    if let Some(rect) = state.ip_rect {
        if let Some(jail) = state.selected_jail() {
            if let Some(index) = list_index_from_mouse(mouse.column, mouse.row, rect, jail.ips.len()) {
                state.focus = Focus::Ips;
                state.ip_state.select(Some(index));
                if let Some(ip) = state.selected_ip() {
                    state.confirm_unban = Some(ip.to_string());
                }
                return Ok(false);
            }
        }
    }

    Ok(false)
}

fn list_index_from_mouse(x: u16, y: u16, area: Rect, len: usize) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let inner = Rect {
        x: area.x + 1,
        y: area.y + 1,
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(2),
    };
    if !point_in_rect(x, y, inner) {
        return None;
    }
    let row = y.saturating_sub(inner.y) as usize;
    if row >= len {
        return None;
    }
    Some(row)
}

fn point_in_rect(x: u16, y: u16, rect: Rect) -> bool {
    x >= rect.x
        && x < rect.x.saturating_add(rect.width)
        && y >= rect.y
        && y < rect.y.saturating_add(rect.height)
}
