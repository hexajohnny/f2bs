use std::collections::HashSet;
use std::io;
use std::net::IpAddr;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
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
struct TimeValue {
    raw: String,
    seconds: Option<u64>,
}

#[derive(Debug, Clone)]
struct IpEntry {
    ip: String,
    end_epoch: Option<i64>,
    time_raw: Option<String>,
}

#[derive(Debug, Clone)]
struct JailStatus {
    name: String,
    ips: Vec<IpEntry>,
    bantime: TimeValue,
    findtime: TimeValue,
    maxretry: Option<u32>,
    currently_banned: Option<u32>,
    total_banned: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortMode {
    Ip,
    TimeLeft,
}

#[derive(Debug, Clone)]
enum Modal {
    UnbanIp { jail: String, ip: String },
    UnbanAll { jail: String, step: u8 },
    BanIp { jail: String, input: String, error: Option<String> },
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

#[derive(Debug)]
struct UiState {
    jails: Vec<JailStatus>,
    jail_state: ListState,
    ip_state: ListState,
    focus: Focus,
    status: String,
    modal: Option<Modal>,
    search_query: String,
    search_mode: bool,
    sort_mode: SortMode,
    autorefresh: bool,
    refresh_interval: Duration,
    last_refresh: Instant,
    jail_rect: Option<Rect>,
    ip_rect: Option<Rect>,
    modal_yes_rect: Option<Rect>,
    modal_no_rect: Option<Rect>,
}

impl UiState {
    fn new() -> Self {
        let mut state = Self::default();
        state.focus = Focus::Jails;
        state.sort_mode = SortMode::Ip;
        state.autorefresh = false;
        state.refresh_interval = Duration::from_secs(5);
        state.last_refresh = Instant::now();
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

    fn selected_ip<'a>(&self, view: &'a [&'a IpEntry]) -> Option<&'a IpEntry> {
        view.get(self.selected_ip_index()).copied()
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
                self.last_refresh = Instant::now();
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
        let view = current_ip_view(self, jail);
        if view.is_empty() {
            return;
        }
        let len = view.len() as i32;
        let current = self.ip_state.selected().unwrap_or(0) as i32;
        let next = (current + delta).clamp(0, len.saturating_sub(1));
        self.ip_state.select(Some(next as usize));
    }
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            jails: Vec::new(),
            jail_state: ListState::default(),
            ip_state: ListState::default(),
            focus: Focus::default(),
            status: String::new(),
            modal: None,
            search_query: String::new(),
            search_mode: false,
            sort_mode: SortMode::Ip,
            autorefresh: false,
            refresh_interval: Duration::from_secs(5),
            last_refresh: Instant::now(),
            jail_rect: None,
            ip_rect: None,
            modal_yes_rect: None,
            modal_no_rect: None,
        }
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

fn parse_status_counts(output: &str) -> (Option<u32>, Option<u32>) {
    let mut current = None;
    let mut total = None;
    for line in output.lines() {
        if let Some((_, tail)) = line.split_once("Currently banned:") {
            current = tail.trim().parse::<u32>().ok();
        } else if let Some((_, tail)) = line.split_once("Total banned:") {
            total = tail.trim().parse::<u32>().ok();
        }
    }
    (current, total)
}

fn parse_time_value(output: &str) -> TimeValue {
    let raw = output.trim().to_string();
    if raw.is_empty() {
        return TimeValue {
            raw: "n/a".to_string(),
            seconds: None,
        };
    }
    let seconds = raw.parse::<u64>().ok();
    TimeValue { raw, seconds }
}

fn parse_maxretry(output: &str) -> Option<u32> {
    output.trim().parse::<u32>().ok()
}

fn parse_time_to_epoch(time_str: &str, bantime_secs: Option<u64>) -> Option<i64> {
    let cleaned = time_str.trim().trim_matches(&[',', ';'][..]);
    if cleaned.is_empty() {
        return None;
    }
    if cleaned.chars().all(|c| c.is_ascii_digit()) {
        let epoch = cleaned.parse::<i64>().ok()?;
        return Some(resolve_end_epoch(epoch, bantime_secs));
    }

    let candidates = [
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
    ];

    if let Some((date, time, tz)) = extract_last_datetime(cleaned) {
        if let Some(tz) = tz {
            let stamp = format!("{date} {time} {tz}");
            if let Ok(dt) = DateTime::parse_from_str(&stamp, "%Y-%m-%d %H:%M:%S %z") {
                let epoch = dt.with_timezone(&Utc).timestamp();
                return Some(resolve_end_epoch(epoch, bantime_secs));
            }
        } else if let Ok(dt) = NaiveDateTime::parse_from_str(
            &format!("{date} {time}"),
            "%Y-%m-%d %H:%M:%S",
        ) {
            let epoch = DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).timestamp();
            return Some(resolve_end_epoch(epoch, bantime_secs));
        }
    }

    for fmt in candidates {
        if let Ok(dt) = DateTime::parse_from_str(cleaned, fmt) {
            let epoch = dt.with_timezone(&Utc).timestamp();
            return Some(resolve_end_epoch(epoch, bantime_secs));
        }
    }

    if let Ok(dt) = NaiveDateTime::parse_from_str(cleaned, "%Y-%m-%d %H:%M:%S") {
        let epoch = DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).timestamp();
        return Some(resolve_end_epoch(epoch, bantime_secs));
    }

    None
}

fn extract_last_datetime(input: &str) -> Option<(String, String, Option<String>)> {
    let parts: Vec<&str> = input.split_whitespace().collect();
    let mut last: Option<(String, String, Option<String>)> = None;
    let mut i = 0;
    while i + 1 < parts.len() {
        let date = parts[i];
        let time = parts[i + 1];
        if looks_like_date(date) && looks_like_time(time) {
            let tz = if i + 2 < parts.len() && looks_like_tz(parts[i + 2]) {
                Some(parts[i + 2].to_string())
            } else {
                None
            };
            last = Some((date.to_string(), time.to_string(), tz));
        }
        i += 1;
    }
    last
}

fn looks_like_date(input: &str) -> bool {
    if input.len() != 10 {
        return false;
    }
    let bytes = input.as_bytes();
    bytes[4] == b'-'
        && bytes[7] == b'-'
        && input
            .chars()
            .enumerate()
            .all(|(i, c)| (i == 4 || i == 7) || c.is_ascii_digit())
}

fn looks_like_time(input: &str) -> bool {
    if input.len() != 8 {
        return false;
    }
    let bytes = input.as_bytes();
    bytes[2] == b':' && bytes[5] == b':' && input.chars().filter(|c| *c != ':').all(|c| c.is_ascii_digit())
}

fn looks_like_tz(input: &str) -> bool {
    if input.len() < 5 {
        return false;
    }
    let first = input.chars().next().unwrap_or(' ');
    if first != '+' && first != '-' {
        return false;
    }
    input[1..].chars().all(|c| c.is_ascii_digit() || c == ':')
}

fn resolve_end_epoch(epoch: i64, bantime_secs: Option<u64>) -> i64 {
    let now = Utc::now().timestamp();
    if epoch >= now {
        return epoch;
    }
    if let Some(bantime) = bantime_secs {
        return epoch.saturating_add(bantime as i64);
    }
    epoch
}

fn parse_banip_with_time(output: &str, bantime_secs: Option<u64>) -> Vec<IpEntry> {
    let mut entries = Vec::new();
    let mut current_ip: Option<String> = None;
    let mut time_tokens: Vec<&str> = Vec::new();

    for token in output.split_whitespace() {
        if token.parse::<IpAddr>().is_ok() {
            if let Some(ip) = current_ip.take() {
                let time_str = time_tokens.join(" ");
                let end_epoch = parse_time_to_epoch(&time_str, bantime_secs);
                entries.push(IpEntry {
                    ip,
                    end_epoch,
                    time_raw: if time_str.is_empty() { None } else { Some(time_str) },
                });
                time_tokens.clear();
            }
            current_ip = Some(token.to_string());
        } else if current_ip.is_some() {
            time_tokens.push(token);
        }
    }

    if let Some(ip) = current_ip {
        let time_str = time_tokens.join(" ");
        let end_epoch = parse_time_to_epoch(&time_str, bantime_secs);
        entries.push(IpEntry {
            ip,
            end_epoch,
            time_raw: if time_str.is_empty() { None } else { Some(time_str) },
        });
    }

    entries
}

fn ips_from_status(output: &str) -> Vec<IpEntry> {
    parse_banned_ips(output)
        .into_iter()
        .map(|ip| IpEntry {
            ip,
            end_epoch: None,
            time_raw: None,
        })
        .collect()
}

fn fetch_status() -> Result<Vec<JailStatus>> {
    let status = run_fail2ban(&["status"])?;
    let jails = parse_jail_list(&status);
    let mut results = Vec::new();
    for jail in jails {
        let jail_status = run_fail2ban(&["status", &jail])?;
        let (currently_banned, total_banned) = parse_status_counts(&jail_status);
        let bantime = run_fail2ban(&["get", &jail, "bantime"])
            .map(|v| parse_time_value(&v))
            .unwrap_or(TimeValue {
                raw: "n/a".to_string(),
                seconds: None,
            });
        let findtime = run_fail2ban(&["get", &jail, "findtime"])
            .map(|v| parse_time_value(&v))
            .unwrap_or(TimeValue {
                raw: "n/a".to_string(),
                seconds: None,
            });
        let maxretry = run_fail2ban(&["get", &jail, "maxretry"])
            .ok()
            .and_then(|v| parse_maxretry(&v));

        let ips = run_fail2ban(&["get", &jail, "banip", "--with-time"])
            .map(|output| parse_banip_with_time(&output, bantime.seconds))
            .unwrap_or_else(|_| ips_from_status(&jail_status));

        results.push(JailStatus {
            name: jail,
            ips,
            bantime,
            findtime,
            maxretry,
            currently_banned,
            total_banned,
        });
    }
    results.sort_by(|a, b| b.ips.len().cmp(&a.ips.len()).then_with(|| a.name.cmp(&b.name)));
    Ok(results)
}

fn draw_ui(frame: &mut ratatui::Frame, state: &mut UiState) {
    let size = frame.area();
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(4),
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

    let details = render_details(state);
    frame.render_widget(details, layout[2]);

    let footer = render_footer(state, layout[3].width);
    frame.render_widget(footer, layout[3]);

    if let Some(modal) = state.modal.clone() {
        render_modal(frame, size, modal, state);
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
    if let Some(jail_index) = state.jail_state.selected() {
        let view_len = {
            let jail = state.jails.get(jail_index);
            jail.map(|j| current_ip_view(state, j).len()).unwrap_or(0)
        };
        if view_len == 0 {
            state.ip_state.select(None);
        } else if state.ip_state.selected().unwrap_or(0) >= view_len {
            state.ip_state.select(Some(view_len.saturating_sub(1)));
        }
        let view = {
            let jail = state.jails.get(jail_index);
            jail.map(|j| current_ip_view(state, j)).unwrap_or_default()
        };
        if view.is_empty() {
            items.push(ListItem::new("No banned IPs"));
        } else {
            let inner_width = area.width.saturating_sub(4) as usize;
            for entry in view {
                let remaining = format_remaining(entry.end_epoch, entry.time_raw.as_deref());
                let label = format_ip_line(&entry.ip, &remaining, inner_width);
                items.push(ListItem::new(label));
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

fn render_footer(state: &UiState, width: u16) -> Paragraph<'_> {
    let help = [
        ("q", " quit  "),
        ("r", " refresh  "),
        ("/", " filter  "),
        ("x", " clear  "),
        ("s", " sort  "),
        ("b", " ban  "),
        ("tab", " switch panel  "),
        ("enter", " unban  "),
        ("A", " unban all  "),
        ("t", " auto"),
    ];
    let mut spans: Vec<Span<'_>> = Vec::new();
    for (key, label) in help {
        spans.push(Span::styled(
            key,
            Style::default()
                .fg(Color::Rgb(255, 184, 108))
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(label));
    }
    let help_line_base = Line::from(spans);
    let version = format!("v{}", env!("CARGO_PKG_VERSION"));
    let inner_width = width.saturating_sub(2) as usize;
    let help_len = help_line_base.width();
    let mut help_line = help_line_base.clone();
    let mut version_in_help = false;
    if inner_width > help_len + version.len() + 1 {
        let spaces = inner_width - help_len - version.len();
        help_line = help_line_base
            .spans
            .into_iter()
            .chain(std::iter::once(Span::raw(" ".repeat(spaces))))
            .chain(std::iter::once(Span::styled(
                version.clone(),
                Style::default().fg(Color::Rgb(160, 160, 160)),
            )))
            .collect();
        version_in_help = true;
    }

    let mut status_line = state.status.clone();
    if !state.search_query.is_empty() || state.search_mode {
        let filter = if state.search_mode {
            format!("Filter: {}_", state.search_query)
        } else {
            format!("Filter: {}", state.search_query)
        };
        status_line = format!("{status_line}  |  {filter}");
    }
    let sort_label = match state.sort_mode {
        SortMode::Ip => "IP",
        SortMode::TimeLeft => "Time Left",
    };
    let auto_label = if state.autorefresh { "Auto: on" } else { "Auto: off" };
    status_line = format!("{status_line}  |  Sort: {sort_label}  |  {auto_label}");
    if !version_in_help {
        status_line = format!("{status_line}  |  {version}");
    }

    let status = Line::from(Span::styled(
        status_line,
        Style::default().fg(Color::Rgb(180, 180, 180)),
    ));

    Paragraph::new(Text::from(vec![help_line, status]))
        .block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(Color::Rgb(80, 80, 80))),
        )
        .wrap(Wrap { trim: true })
}

fn render_details(state: &UiState) -> Paragraph<'_> {
    let title = if let Some(jail) = state.selected_jail() {
        format!("Jail Details - {}", jail.name)
    } else {
        "Jail Details".to_string()
    };

    let mut lines = Vec::new();
    if let Some(jail) = state.selected_jail() {
        let bantime = format_time_value(&jail.bantime);
        let findtime = format_time_value(&jail.findtime);
        let maxretry = jail
            .maxretry
            .map(|v| v.to_string())
            .unwrap_or_else(|| "n/a".to_string());
        let current = jail
            .currently_banned
            .map(|v| v.to_string())
            .unwrap_or_else(|| "n/a".to_string());
        let total = jail
            .total_banned
            .map(|v| v.to_string())
            .unwrap_or_else(|| "n/a".to_string());
        let recidive = if jail.name.eq_ignore_ascii_case("recidive") {
            "yes"
        } else {
            "no"
        };

        lines.push(Line::from(Span::raw(format!(
            "Bantime: {bantime}  |  Findtime: {findtime}  |  Maxretry: {maxretry}"
        ))));
        lines.push(Line::from(Span::raw(format!(
            "Currently banned: {current}  |  Total banned: {total}  |  Recidive jail: {recidive}"
        ))));
    } else {
        lines.push(Line::from(Span::raw("Select a jail to see details")));
    }

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(80, 80, 80))),
        )
        .wrap(Wrap { trim: true })
}

fn render_modal(frame: &mut ratatui::Frame, area: Rect, modal: Modal, state: &mut UiState) {
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

    let lines = match modal {
        Modal::UnbanIp { ref jail, ref ip } => vec![
            Line::from(Span::styled(
                "Confirm Unban",
                Style::default().fg(Color::Rgb(255, 184, 108)).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::raw("")),
            Line::from(Span::raw(format!("Unban {ip} from {jail}?"))),
            Line::from(Span::raw("")),
            Line::from(Span::raw("Press y/n or click a button")),
        ],
        Modal::UnbanAll { ref jail, step } => {
            let headline = if step == 1 {
                "Confirm Unban All"
            } else {
                "Confirm Unban All (Final)"
            };
            let warning = if step == 1 {
                format!("Unban ALL IPs in {jail}?")
            } else {
                format!("This will remove all bans in {jail}. Proceed?")
            };
            vec![
                Line::from(Span::styled(
                    headline,
                    Style::default().fg(Color::Rgb(255, 184, 108)).add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::raw("")),
                Line::from(Span::raw(warning)),
                Line::from(Span::raw("")),
                Line::from(Span::raw("Press y/n or click a button")),
            ]
        }
        Modal::BanIp {
            ref jail,
            ref input,
            ref error,
        } => {
            let mut lines = vec![
                Line::from(Span::styled(
                    "Ban IP",
                    Style::default().fg(Color::Rgb(255, 184, 108)).add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::raw("")),
                Line::from(Span::raw(format!("Jail: {jail}"))),
                Line::from(Span::raw("")),
                Line::from(Span::raw(format!("IP: {input}_"))),
            ];
            if let Some(err) = error {
                lines.push(Line::from(Span::raw("")));
                lines.push(Line::from(Span::styled(
                    err.clone(),
                    Style::default().fg(Color::Rgb(240, 120, 120)),
                )));
            } else {
                lines.push(Line::from(Span::raw("")));
                lines.push(Line::from(Span::raw("Type IP, press enter to ban, esc to cancel")));
            }
            lines
        }
    };

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

fn format_time_value(value: &TimeValue) -> String {
    if let Some(seconds) = value.seconds {
        if value.raw.parse::<u64>().is_ok() {
            return format!("{}s ({})", value.raw, format_duration(seconds));
        }
        return format!("{} ({})", value.raw, format_duration(seconds));
    }
    value.raw.clone()
}

fn format_duration(mut seconds: u64) -> String {
    if seconds == 0 {
        return "0s".to_string();
    }
    let days = seconds / 86_400;
    seconds %= 86_400;
    let hours = seconds / 3600;
    seconds %= 3600;
    let minutes = seconds / 60;
    let secs = seconds % 60;

    let mut out = String::new();
    if days > 0 {
        out.push_str(&format!("{days}d"));
    }
    if hours > 0 {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&format!("{hours}h"));
    }
    if minutes > 0 {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&format!("{minutes}m"));
    }
    if secs > 0 && out.is_empty() {
        out.push_str(&format!("{secs}s"));
    }
    out
}

fn format_duration_compact(mut seconds: u64) -> String {
    if seconds == 0 {
        return "0s".to_string();
    }
    let days = seconds / 86_400;
    seconds %= 86_400;
    let hours = seconds / 3600;
    seconds %= 3600;
    let minutes = seconds / 60;
    let secs = seconds % 60;

    let mut out = String::new();
    if days > 0 {
        out.push_str(&format!("{days}d"));
    }
    if hours > 0 {
        out.push_str(&format!("{hours}h"));
    }
    if minutes > 0 {
        out.push_str(&format!("{minutes}m"));
    }
    if secs > 0 && out.is_empty() {
        out.push_str(&format!("{secs}s"));
    }
    out
}

fn format_remaining(end_epoch: Option<i64>, raw: Option<&str>) -> String {
    if let Some(end_epoch) = end_epoch {
        let now = Utc::now().timestamp();
        let remaining = if end_epoch <= now {
            0
        } else {
            (end_epoch - now) as u64
        };
        return format!("({})", format_duration_compact(remaining));
    }
    if let Some(raw) = raw {
        let raw = raw.trim();
        if !raw.is_empty() {
            if let Some(seconds) = parse_duration_string(raw) {
                return format!("({})", format_duration_compact(seconds));
            }
            return raw.to_string();
        }
    }
    "--".to_string()
}

fn parse_duration_string(input: &str) -> Option<u64> {
    let mut total = 0u64;
    let mut num: Option<u64> = None;
    let mut has_unit = false;

    for ch in input.chars() {
        if ch.is_ascii_digit() {
            let digit = ch.to_digit(10)? as u64;
            num = Some(num.unwrap_or(0) * 10 + digit);
        } else {
            let Some(value) = num.take() else {
                continue;
            };
            match ch {
                'w' | 'W' => {
                    total += value * 7 * 86_400;
                    has_unit = true;
                }
                'd' | 'D' => {
                    total += value * 86_400;
                    has_unit = true;
                }
                'h' | 'H' => {
                    total += value * 3600;
                    has_unit = true;
                }
                'm' | 'M' => {
                    total += value * 60;
                    has_unit = true;
                }
                's' | 'S' => {
                    total += value;
                    has_unit = true;
                }
                _ => {}
            }
        }
    }

    if let Some(value) = num {
        total += value;
    }

    if has_unit {
        Some(total)
    } else {
        None
    }
}

fn format_ip_line(ip: &str, remaining: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let rem_len = remaining.len();
    if rem_len >= width {
        return remaining.chars().take(width).collect();
    }

    let available = width - rem_len;
    let mut ip_part = ip.to_string();
    if ip_part.len() > available {
        let trunc = available.saturating_sub(3);
        if trunc == 0 {
            ip_part.clear();
        } else {
            ip_part.truncate(trunc);
            ip_part.push_str("...");
        }
    }
    let spaces = available.saturating_sub(ip_part.len());
    format!("{ip_part}{}{}", " ".repeat(spaces), remaining)
}

fn remaining_seconds(end_epoch: Option<i64>) -> Option<u64> {
    let end_epoch = end_epoch?;
    let now = Utc::now().timestamp();
    if end_epoch <= now {
        Some(0)
    } else {
        Some((end_epoch - now) as u64)
    }
}

fn current_ip_view<'a>(state: &UiState, jail: &'a JailStatus) -> Vec<&'a IpEntry> {
    let query = state.search_query.trim().to_lowercase();
    let mut view: Vec<&IpEntry> = jail
        .ips
        .iter()
        .filter(|entry| {
            if query.is_empty() {
                true
            } else {
                entry.ip.to_lowercase().contains(&query)
            }
        })
        .collect();

    match state.sort_mode {
        SortMode::Ip => {
            view.sort_by(|a, b| a.ip.cmp(&b.ip));
        }
        SortMode::TimeLeft => {
            view.sort_by_key(|entry| remaining_seconds(entry.end_epoch).unwrap_or(u64::MAX));
        }
    }

    view
}

fn unban_all_in_jail(state: &UiState, jail: &str) -> Result<usize> {
    let Some(jail_status) = state.jails.iter().find(|j| j.name == jail) else {
        return Err(anyhow!("jail not found"));
    };
    if jail_status.ips.is_empty() {
        return Ok(0);
    }

    let mut total = 0;
    for chunk in jail_status.ips.chunks(50) {
        let mut args: Vec<String> = Vec::with_capacity(3 + chunk.len());
        args.push("set".to_string());
        args.push(jail.to_string());
        args.push("unbanip".to_string());
        for entry in chunk {
            args.push(entry.ip.clone());
        }
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        run_fail2ban(&refs)?;
        total += chunk.len();
    }

    Ok(total)
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
        if state.autorefresh && state.last_refresh.elapsed() >= state.refresh_interval {
            state.refresh();
        }
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

    if let Some(modal) = state.modal.clone() {
        return handle_modal_key(key, state, modal);
    }

    if state.search_mode {
        return handle_search_key(key, state);
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Char('Q') => return Ok(true),
        KeyCode::Char('r') | KeyCode::Char('R') => state.refresh(),
        KeyCode::Char('t') | KeyCode::Char('T') => {
            state.autorefresh = !state.autorefresh;
            state.set_status(if state.autorefresh {
                "Auto-refresh enabled"
            } else {
                "Auto-refresh disabled"
            });
        }
        KeyCode::Char('s') | KeyCode::Char('S') => {
            state.sort_mode = match state.sort_mode {
                SortMode::Ip => SortMode::TimeLeft,
                SortMode::TimeLeft => SortMode::Ip,
            };
            state.ip_state.select(Some(0));
            state.set_status("Sort mode updated");
        }
        KeyCode::Char('b') | KeyCode::Char('B') => {
            if let Some(jail) = state.selected_jail() {
                state.modal = Some(Modal::BanIp {
                    jail: jail.name.clone(),
                    input: String::new(),
                    error: None,
                });
                state.set_status("Enter IP to ban");
            }
        }
        KeyCode::Char('/') => {
            state.search_mode = true;
        }
        KeyCode::Char('x') | KeyCode::Char('X') => {
            state.search_query.clear();
            state.ip_state.select(Some(0));
            state.set_status("Filter cleared");
        }
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
            } else if let Some(jail) = state.selected_jail() {
                let view = current_ip_view(state, jail);
                if let Some(entry) = state.selected_ip(&view) {
                    state.modal = Some(Modal::UnbanIp {
                        jail: jail.name.clone(),
                        ip: entry.ip.clone(),
                    });
                }
            }
        }
        KeyCode::Char('u') | KeyCode::Char('U') => {
            if let Some(jail) = state.selected_jail() {
                let view = current_ip_view(state, jail);
                if let Some(entry) = state.selected_ip(&view) {
                    state.modal = Some(Modal::UnbanIp {
                        jail: jail.name.clone(),
                        ip: entry.ip.clone(),
                    });
                }
            }
        }
        KeyCode::Char('A') => {
            if let Some(jail) = state.selected_jail() {
                state.modal = Some(Modal::UnbanAll {
                    jail: jail.name.clone(),
                    step: 1,
                });
            }
        }
        KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::SHIFT) => {
            if let Some(jail) = state.selected_jail() {
                state.modal = Some(Modal::UnbanAll {
                    jail: jail.name.clone(),
                    step: 1,
                });
            }
        }
        _ => {}
    }

    Ok(false)
}

fn handle_search_key(key: KeyEvent, state: &mut UiState) -> Result<bool> {
    match key.code {
        KeyCode::Esc => {
            state.search_mode = false;
            state.set_status("Filter canceled");
        }
        KeyCode::Enter => {
            state.search_mode = false;
            state.ip_state.select(Some(0));
            state.set_status("Filter applied");
        }
        KeyCode::Backspace => {
            state.search_query.pop();
        }
        KeyCode::Char(c) => {
            if !key.modifiers.contains(KeyModifiers::CONTROL) {
                state.search_query.push(c);
            }
        }
        _ => {}
    }
    Ok(false)
}

fn handle_modal_key(key: KeyEvent, state: &mut UiState, modal: Modal) -> Result<bool> {
    if let Modal::BanIp { jail, mut input, .. } = modal
    {
        match key.code {
            KeyCode::Esc => {
                state.modal = None;
                state.set_status("Action canceled");
                return Ok(false);
            }
            KeyCode::Backspace => {
                input.pop();
            }
            KeyCode::Char(c) => {
                if !key.modifiers.contains(KeyModifiers::CONTROL) {
                    input.push(c);
                }
            }
            KeyCode::Enter => {
                let ip = input.trim().to_string();
                if ip.parse::<IpAddr>().is_err() {
                    state.modal = Some(Modal::BanIp {
                        jail,
                        input,
                        error: Some("Invalid IP address".to_string()),
                    });
                    return Ok(false);
                }
                match run_fail2ban(&["set", &jail, "banip", &ip]) {
                    Ok(_) => {
                        state.set_status(format!("Banned {ip} in {jail}"));
                        state.modal = None;
                        state.refresh();
                    }
                    Err(err) => {
                        state.modal = Some(Modal::BanIp {
                            jail,
                            input,
                            error: Some(format!("Ban failed: {err}")),
                        });
                    }
                }
                return Ok(false);
            }
            _ => {}
        }
        state.modal = Some(Modal::BanIp {
            jail,
            input,
            error: None,
        });
        return Ok(false);
    }

    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
            match modal {
                Modal::UnbanIp { jail, ip } => {
                    match run_fail2ban(&["set", &jail, "unbanip", &ip]) {
                        Ok(_) => {
                            state.set_status(format!("Unbanned {ip} from {jail}"));
                            state.modal = None;
                            state.refresh();
                        }
                        Err(err) => {
                            state.set_status(format!("Unban failed for {ip}: {err}"));
                            state.modal = None;
                        }
                    }
                }
                Modal::UnbanAll { jail, step } => {
                    if step == 1 {
                        state.modal = Some(Modal::UnbanAll { jail, step: 2 });
                        state.set_status("Second confirmation required");
                    } else {
                        match unban_all_in_jail(state, &jail) {
                            Ok(count) => {
                                state.set_status(format!("Unbanned {count} IPs from {jail}"));
                                state.modal = None;
                                state.refresh();
                            }
                            Err(err) => {
                                state.set_status(format!("Unban all failed for {jail}: {err}"));
                                state.modal = None;
                            }
                        }
                    }
                }
                Modal::BanIp { .. } => {}
            }
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            state.modal = None;
            state.set_status("Action canceled");
        }
        _ => {}
    }

    Ok(false)
}

fn handle_mouse(mouse: MouseEvent, state: &mut UiState) -> Result<bool> {
    if mouse.kind != MouseEventKind::Down(crossterm::event::MouseButton::Left) {
        return Ok(false);
    }

    if let Some(modal) = state.modal.clone() {
        if let Some(rect) = state.modal_yes_rect {
            if point_in_rect(mouse.column, mouse.row, rect) {
                return handle_modal_key(
                    KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
                    state,
                    modal,
                );
            }
        }
        if let Some(rect) = state.modal_no_rect {
            if point_in_rect(mouse.column, mouse.row, rect) {
                return handle_modal_key(
                    KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()),
                    state,
                    modal,
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
        if let Some(jail_index) = state.jail_state.selected() {
            let (jail_name, view) = if let Some(jail) = state.jails.get(jail_index) {
                (jail.name.clone(), current_ip_view(state, jail))
            } else {
                return Ok(false);
            };
            let maybe_ip = if let Some(index) =
                list_index_from_mouse(mouse.column, mouse.row, rect, view.len())
            {
                state.ip_state.select(Some(index));
                state.selected_ip(&view).map(|entry| entry.ip.clone())
            } else {
                None
            };
            if let Some(ip) = maybe_ip {
                state.focus = Focus::Ips;
                state.modal = Some(Modal::UnbanIp {
                    jail: jail_name,
                    ip,
                });
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
