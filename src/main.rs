mod client;
mod data;

use crossterm::{
    cursor,
    event::{self, Event, KeyCode},
    execute,
    terminal::{self, ClearType},
};
use data::Region;
use std::{
    collections::{HashMap, HashSet},
    io::{self, Write},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use unicode_width::UnicodeWidthChar;

enum Message {
    Loaded(Result<Vec<Region>, String>),
    Timed(String, Result<Duration, String>),
    Firewall(bool, Result<client::Reply, String>),
}

struct App {
    regions: Vec<Region>,
    selected: usize,
    blocked: HashSet<String>,
    times: HashMap<String, Result<Duration, String>>,
    running: HashSet<String>,
    last: HashMap<String, Instant>,
    flows: HashMap<String, usize>,
    details: bool,
    network_index: usize,
    continuous: bool,
    status: String,
    firewall_state: String,
    applying: bool,
    pending_status: bool,
    dirty: bool,
    revision: u64,
    applied_revision: u64,
    tx: mpsc::Sender<Message>,
}

impl App {
    fn new(tx: mpsc::Sender<Message>) -> Self {
        Self {
            regions: vec![],
            selected: 0,
            blocked: HashSet::new(),
            times: HashMap::new(),
            running: HashSet::new(),
            last: HashMap::new(),
            flows: HashMap::new(),
            details: false,
            network_index: 0,
            continuous: false,
            status: "Загружаю регионы…".into(),
            firewall_state: "не проверено".into(),
            applying: false,
            pending_status: false,
            dirty: false,
            revision: 0,
            applied_revision: 0,
            tx,
        }
    }

    fn fetch(&self) {
        let tx = self.tx.clone();
        thread::spawn(move || {
            let result = data::fetch_json(data::IPS_URL).and_then(|ips| {
                data::fetch_json(data::ENDPOINTS_URL)
                    .and_then(|endpoints| data::parse_regions(&ips, &endpoints))
            });
            let _ = tx.send(Message::Loaded(result));
        });
    }

    fn probe(&mut self, code: &str) {
        if !self.running.insert(code.to_string()) {
            return;
        }
        let Some(region) = self.regions.iter().find(|r| r.code == code) else {
            self.running.remove(code);
            return;
        };
        let url = region.url.clone();
        let code = code.to_string();
        let tx = self.tx.clone();
        thread::spawn(move || {
            let result = data::measure_https(&url);
            let _ = tx.send(Message::Timed(code, result));
        });
    }

    fn probe_all(&mut self) {
        for code in self
            .regions
            .iter()
            .map(|r| r.code.clone())
            .collect::<Vec<_>>()
        {
            self.probe(&code)
        }
    }

    fn check_firewall(&mut self) {
        if self.pending_status || self.applying {
            return;
        }
        self.pending_status = true;
        let tx = self.tx.clone();
        thread::spawn(move || {
            let _ = tx.send(Message::Firewall(false, client::send("status", &[])));
        });
    }

    fn apply(&mut self) {
        if self.regions.is_empty() || self.applying || self.pending_status {
            return;
        }
        if !self.blocked.is_empty()
            && self.blocked.len() >= self.regions.iter().filter(|r| !r.legacy).count()
        {
            self.status = "Нельзя заблокировать все игровые регионы".into();
            return;
        }
        let nets: Vec<_> = self
            .regions
            .iter()
            .filter(|r| self.blocked.contains(&r.code))
            .flat_map(|r| r.networks.iter().copied())
            .collect();
        let tx = self.tx.clone();
        self.firewall_state = "применение…".into();
        self.applied_revision = self.revision;
        self.applying = true;
        thread::spawn(move || {
            let _ = tx.send(Message::Firewall(true, client::send("apply", &nets)));
        });
    }

    fn event(&mut self, message: Message) {
        match message {
            Message::Loaded(Ok(regions)) => {
                self.regions = regions;
                self.selected = self.selected.min(self.regions.len().saturating_sub(1));
                self.network_index = 0;
                self.status = format!(
                    "{} регионов • HTTPS-узлы не являются серверами игры",
                    self.regions.len()
                );
                self.probe_all();
                self.check_firewall();
            }
            Message::Loaded(Err(e)) => {
                self.status = format!("Ошибка списка регионов: {e} (R — повторить)")
            }
            Message::Timed(code, value) => {
                self.running.remove(&code);
                self.last.insert(code.clone(), Instant::now());
                self.times.insert(code, value);
            }
            Message::Firewall(applied, Ok(reply)) => {
                if applied {
                    self.applying = false;
                    self.dirty = self.revision != self.applied_revision;
                } else {
                    self.pending_status = false;
                }
                if !applied && !self.dirty {
                    self.blocked = self
                        .regions
                        .iter()
                        .filter(|r| r.networks.iter().any(|n| reply.networks.contains(n)))
                        .map(|r| r.code.clone())
                        .collect();
                    let needs_update = self
                        .regions
                        .iter()
                        .filter(|r| self.blocked.contains(&r.code))
                        .flat_map(|r| &r.networks)
                        .any(|n| {
                            !reply.networks.iter().any(|saved| {
                                saved.prefix_len() <= n.prefix_len() && saved.contains(&n.addr())
                            })
                        });
                    if needs_update {
                        self.dirty = true;
                        self.revision += 1;
                    }
                }
                self.firewall_state =
                    if reply.backend != reply.selected_backend && !reply.networks.is_empty() {
                        format!(
                            "ВНИМАНИЕ: правила в {}, сейчас выбран {}; нажмите a для переноса",
                            reply.backend, reply.selected_backend
                        )
                    } else if self.dirty {
                        "ВНИМАНИЕ: выбор ещё НЕ применён к брандмауэру (a)".into()
                    } else if reply.active {
                        format!(
                            "{}: {} игровых сетей активно",
                            reply.backend,
                            reply.networks.len()
                        )
                    } else {
                        "ВНИМАНИЕ: сохранённые правила брандмауэра отсутствуют!".into()
                    };
            }
            Message::Firewall(applied, Err(e)) => {
                if applied {
                    self.applying = false;
                } else {
                    self.pending_status = false;
                }
                self.firewall_state = format!("ВНИМАНИЕ: {e}");
            }
        }
    }

    fn tick(&mut self) -> bool {
        let mut changed = false;
        if self.continuous {
            let now = Instant::now();
            let due: Vec<_> = self
                .regions
                .iter()
                .filter(|r| {
                    !self.running.contains(&r.code)
                        && self
                            .last
                            .get(&r.code)
                            .is_none_or(|t| now.duration_since(*t) >= Duration::from_secs(5))
                })
                .map(|r| r.code.clone())
                .collect();
            for code in due {
                self.probe(&code);
                changed = true;
            }
        }
        changed
    }

    fn lines(&self, width: usize, height: usize) -> Vec<String> {
        let mut screen = Vec::new();
        if width < 48 || height < 15 {
            screen.push(fit("Dropshit — нужно окно от 48×15", width));
            screen.push(fit(&format!("Сейчас: {width}×{height}  •  q выход"), width));
            return screen;
        }

        screen.push(fit(
            &format!(
                "DROPSHIT {}  •  HTTPS-задержка региона ≠ пинг игры",
                env!("CARGO_PKG_VERSION")
            ),
            width,
        ));
        screen.push(fit(&format!("Список: {}", self.status), width));
        screen.push(fit(&format!("Правила: {}", self.firewall_state), width));
        screen.push(fit(
            &format!(
                "Выбор: {}  •  HTTPS-автозамер: {}",
                if self.dirty {
                    "НЕ ПРИМЕНЁН"
                } else {
                    "без изменений"
                },
                if self.continuous {
                    "вкл"
                } else {
                    "выкл"
                }
            ),
            width,
        ));
        screen.push(fit(&"─".repeat(width.saturating_sub(1)), width));

        let wide = width >= 72;
        if wide {
            let region_width = width.saturating_sub(32);
            screen.push(fit(
                &format!(
                    "     {:<6} {} {:>10} {:>5}",
                    "КОД",
                    padded("РЕГИОН", region_width),
                    "HTTPS",
                    "UDP"
                ),
                width,
            ));
        } else {
            let region_width = width.saturating_sub(25);
            screen.push(fit(
                &format!(
                    "     {:<6} {} {:>10}",
                    "КОД",
                    padded("РЕГИОН", region_width),
                    "HTTPS"
                ),
                width,
            ));
        }

        let footer = 6;
        let visible = height.saturating_sub(screen.len() + footer).max(1);
        let first = self
            .selected
            .saturating_sub(visible / 2)
            .min(self.regions.len().saturating_sub(visible));
        for (idx, region) in self.regions.iter().enumerate().skip(first).take(visible) {
            let mark = if region.legacy {
                "арх"
            } else if self.blocked.contains(&region.code) {
                "[x]"
            } else {
                "[ ]"
            };
            let latency = match self.times.get(&region.code) {
                Some(Ok(ms)) => format!(
                    "{:.0}мс{}",
                    ms.as_secs_f64() * 1000.,
                    if self.running.contains(&region.code) {
                        "*"
                    } else {
                        ""
                    }
                ),
                Some(Err(_)) => "ошибка".into(),
                None => "замер…".into(),
            };
            let region_width = if wide {
                width.saturating_sub(32)
            } else {
                width.saturating_sub(25)
            };
            let prefix = format!(
                "{}{} {:<6} ",
                if idx == self.selected { ">" } else { " " },
                mark,
                region.code
            );
            let row = if wide {
                format!(
                    "{prefix}{} {:>10} {:>5}",
                    padded(&region.title, region_width),
                    latency,
                    self.flows.get(&region.code).copied().unwrap_or(0)
                )
            } else {
                format!(
                    "{prefix}{} {:>10}",
                    padded(&region.title, region_width),
                    latency
                )
            };
            screen.push(fit(&row, width));
        }

        screen.push(fit(&"─".repeat(width.saturating_sub(1)), width));
        if let Some(region) = self.regions.get(self.selected) {
            if self.details {
                let net = region
                    .networks
                    .get(self.network_index % region.networks.len().max(1));
                screen.push(fit(
                    &format!(
                        "{} • {} игровых CIDR • UDP 12000–64000",
                        region.code,
                        region.networks.len()
                    ),
                    width,
                ));
                let host = region.url.strip_prefix("https://").unwrap_or(&region.url);
                screen.push(fit(&format!("HTTPS: {host}"), width));
                let note = if let Some(net) = net {
                    format!(
                        "CIDR {}/{}: {net}  •  n/b",
                        (self.network_index % region.networks.len()) + 1,
                        region.networks.len()
                    )
                } else {
                    "Архив: игровые сети отсутствуют".into()
                };
                screen.push(fit(&note, width));
            } else {
                screen.push(fit(
                    &format!(
                        "{} • {} сетей игры • d — адрес и детали",
                        region.code,
                        region.networks.len()
                    ),
                    width,
                ));
            }
        } else {
            screen.push(fit("Ожидание данных о регионах…", width));
        }
        screen.push(fit("↑↓  Space блок  a применить  u снять  q выход", width));
        screen.push(fit(
            "p/r HTTPS  c авто  s правила  R список  d детали",
            width,
        ));
        screen.truncate(height);
        screen
    }

    fn render(&self, out: &mut impl Write) -> io::Result<()> {
        let (width, height) = terminal::size().unwrap_or((80, 24));
        let lines = self.lines(width as usize, height as usize);
        execute!(out, cursor::MoveTo(0, 0), terminal::Clear(ClearType::All))?;
        for (y, line) in lines.iter().enumerate() {
            execute!(out, cursor::MoveTo(0, y as u16))?;
            write!(out, "{line}")?;
        }
        out.flush()
    }
}

fn fit(text: &str, width: usize) -> String {
    let mut result = String::new();
    let mut used = 0;
    for ch in text.chars() {
        let size = UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + size >= width {
            break;
        }
        result.push(ch);
        used += size;
    }
    result
}

fn padded(text: &str, width: usize) -> String {
    let mut result = fit(text, width + 1);
    let mut used = result
        .chars()
        .map(|c| UnicodeWidthChar::width(c).unwrap_or(0))
        .sum::<usize>();
    while used > width {
        if let Some(last) = result.pop() {
            used -= UnicodeWidthChar::width(last).unwrap_or(0);
        }
    }
    result.push_str(&" ".repeat(width.saturating_sub(used)));
    result
}

struct Terminal;
impl Terminal {
    fn enter() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        execute!(io::stdout(), terminal::EnterAlternateScreen, cursor::Hide)?;
        Ok(Self)
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), cursor::Show, terminal::LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;

    #[test]
    fn saved_region_missing_new_peer_requires_reapply() {
        let (tx, _rx) = mpsc::channel();
        let mut app = App::new(tx);
        app.regions = vec![Region {
            code: "ams1".into(),
            title: "Netherlands".into(),
            url: String::new(),
            networks: vec![
                "64.224.26.0/23".parse().unwrap(),
                "66.40.191.240/32".parse().unwrap(),
            ],
            legacy: false,
        }];
        let reply = |networks: Vec<_>| client::Reply {
            backend: "nftables".into(),
            selected_backend: "nftables".into(),
            networks,
            active: true,
        };
        app.event(Message::Firewall(
            false,
            Ok(reply(vec!["64.224.26.0/23".parse().unwrap()])),
        ));
        assert!(app.blocked.contains("ams1"));
        assert!(app.dirty);
        assert!(app.firewall_state.contains("НЕ применён"));
        app.applied_revision = app.revision;
        app.event(Message::Firewall(
            true,
            Ok(reply(app.regions[0].networks.clone())),
        ));
        assert!(!app.dirty);
        assert!(app.firewall_state.contains("активно"));
    }

    #[test]
    fn no_line_wraps_or_overruns_small_terminal() {
        let (tx, _rx) = mpsc::channel();
        let mut app = App::new(tx);
        app.regions = (0..12)
            .map(|i| Region {
                code: format!("test{i}"),
                title: "Очень длинное название региона 大阪".into(),
                url: "https://very-long-regional-host.example.org/".into(),
                networks: (0..65)
                    .map(|n| format!("192.0.{n}.0/24").parse().unwrap())
                    .collect(),
                legacy: false,
            })
            .collect();
        app.selected = 11;
        app.details = true;
        app.network_index = 64;
        app.firewall_state =
            "ВНИМАНИЕ: очень длинное уведомление с повторяющимся текстом".repeat(5);
        for (width, height) in [(40, 10), (48, 15), (60, 18), (80, 24), (120, 30)] {
            let lines = app.lines(width, height);
            assert!(lines.len() <= height);
            for line in &lines {
                assert!(
                    line.chars()
                        .map(|c| UnicodeWidthChar::width(c).unwrap_or(0))
                        .sum::<usize>()
                        < width,
                    "{width}×{height}: {line:?}"
                );
            }
            if width >= 48 && height >= 15 {
                assert!(lines.iter().any(|line| line.contains("test11")));
                assert!(lines.iter().any(|line| line.contains("q выход")));
                assert!(lines.iter().any(|line| line.contains("CIDR 65/65")));
                let row = lines.iter().find(|line| line.contains("test11")).unwrap();
                assert!(
                    row.contains("замер"),
                    "HTTPS column should remain visible: {row}"
                );
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|a| a == "--help") {
        println!(
            "Dropshit TUI: стрелки — регион, пробел — блокировка, a — применить, u — снять, s — проверить правила, p/r — HTTPS-замер, c — постоянный замер, d — детали, n/b — игровые сети, R — обновить список, q — выход. Требуются curl, iproute2 и терминал."
        );
        return Ok(());
    }
    let _terminal = Terminal::enter()?;
    let (tx, rx) = mpsc::channel();
    let mut app = App::new(tx);
    app.fetch();
    let mut last_flow_check = Instant::now() - Duration::from_secs(10);
    let mut redraw = true;
    loop {
        while let Ok(msg) = rx.try_recv() {
            app.event(msg);
            redraw = true;
        }
        redraw |= app.tick();
        if last_flow_check.elapsed() >= Duration::from_secs(3) {
            let flows = data::observe_udp(&app.regions);
            if flows != app.flows {
                app.flows = flows;
                redraw = true;
            }
            last_flow_check = Instant::now();
        }
        if redraw {
            app.render(&mut io::stdout())?;
            redraw = false;
        }
        if event::poll(Duration::from_millis(200))? {
            let input = event::read()?;
            if matches!(input, Event::Resize(_, _)) {
                redraw = true;
            }
            if let Event::Key(key) = input {
                redraw = true;
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Down | KeyCode::Char('j') => {
                        app.selected = (app.selected + 1).min(app.regions.len().saturating_sub(1));
                        app.network_index = 0;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        app.selected = app.selected.saturating_sub(1);
                        app.network_index = 0;
                    }
                    KeyCode::Char(' ') => {
                        if let Some(r) = app.regions.get(app.selected) {
                            if !r.legacy {
                                let code = r.code.clone();
                                if !app.blocked.insert(code.clone()) {
                                    app.blocked.remove(&code);
                                }
                                app.revision = app.revision.wrapping_add(1);
                                app.dirty = true;
                                app.firewall_state =
                                    "ВНИМАНИЕ: выбор ещё НЕ применён к брандмауэру (a)".into();
                                app.status = "Выбор изменён; нажмите a для применения".into();
                            }
                        }
                    }
                    KeyCode::Char('p') => {
                        if let Some(r) = app.regions.get(app.selected) {
                            let code = r.code.clone();
                            app.probe(&code)
                        }
                    }
                    KeyCode::Char('r') => app.probe_all(),
                    KeyCode::Char('d') => app.details = !app.details,
                    KeyCode::Char('n') => app.network_index = app.network_index.wrapping_add(1),
                    KeyCode::Char('b') => app.network_index = app.network_index.wrapping_sub(1),
                    KeyCode::Char('s') => app.check_firewall(),
                    KeyCode::Char('c') => app.continuous = !app.continuous,
                    KeyCode::Char('R') => app.fetch(),
                    KeyCode::Char('a') => app.apply(),
                    KeyCode::Char('u') => {
                        app.blocked.clear();
                        app.revision = app.revision.wrapping_add(1);
                        app.dirty = true;
                        app.apply()
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}
