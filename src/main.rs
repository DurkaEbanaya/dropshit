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

    fn tick(&mut self) {
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
                self.probe(&code)
            }
        }
    }

    fn render(&self, out: &mut impl Write) -> io::Result<()> {
        let (width, height) = terminal::size().unwrap_or((100, 30));
        execute!(out, cursor::MoveTo(0, 0), terminal::Clear(ClearType::All))?;
        writeln!(
            out,
            "Dropshit 0.1.0 — региональная HTTPS-задержка (НЕ пинг Overwatch)"
        )?;
        writeln!(out, "Статус: {}", self.status)?;
        writeln!(out, "Правила: {}", self.firewall_state)?;
        writeln!(
            out,
            "↑↓ выбор  Пробел блок/разблок  a применить  u снять все  s проверить правила  p/r HTTPS  c постоянно [{}]  R список  q выход",
            if self.continuous { "да" } else { "нет" }
        )?;
        writeln!(
            out,
            "{:<4} {:<6} {:<26} {:<35} {:<12} {}",
            "", "код", "регион", "HTTPS-адрес :443", "задержка", "UDP потоки"
        )?;
        if width < 86 || height < 17 {
            writeln!(
                out,
                "Увеличьте окно терминала до 86×17 (сейчас {width}×{height})"
            )?;
            return out.flush();
        }
        let visible = (height as usize).saturating_sub(13).max(1);
        let first = self
            .selected
            .saturating_sub(visible / 2)
            .min(self.regions.len().saturating_sub(visible));
        for (idx, region) in self.regions.iter().enumerate().skip(first).take(visible) {
            let indicator = if region.legacy {
                "арх"
            } else if self.blocked.contains(&region.code) {
                "[x]"
            } else {
                "[ ]"
            };
            let ping = if let Some(Ok(time)) = self.times.get(&region.code) {
                format!(
                    "{:.0} мс{}",
                    time.as_secs_f64() * 1000.,
                    if self.running.contains(&region.code) {
                        " ↻"
                    } else {
                        ""
                    }
                )
            } else if let Some(Err(_)) = self.times.get(&region.code) {
                "нет ответа".into()
            } else {
                "ожидание…".into()
            };
            let host = region
                .url
                .trim_start_matches("https://")
                .trim_end_matches('/');
            writeln!(
                out,
                "{}{} {:<6} {:<26} {:<35} {:<12} {}",
                if idx == self.selected { ">" } else { " " },
                indicator,
                region.code,
                region.title,
                host,
                ping,
                self.flows.get(&region.code).copied().unwrap_or(0)
            )?;
        }
        if let Some(region) = self.regions.get(self.selected) {
            writeln!(
                out,
                "\nРегион {}: тестовый HTTPS {}",
                region.code, region.url
            )?;
            writeln!(
                out,
                "Сети игры (UDP 12000–64000): {}",
                region
                    .networks
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )?;
            if region.code == "ord1" {
                writeln!(
                    out,
                    "Iowa — географический суррогат; не точный игровой дата-центр"
                )?
            }
            if region.legacy {
                writeln!(
                    out,
                    "Архивная локация: в актуальном списке игровых сетей отсутствует"
                )?
            }
            if let Some(Err(e)) = self.times.get(&region.code) {
                writeln!(out, "HTTPS-ошибка: {e}")?
            }
        }
        out.flush()
    }
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|a| a == "--help") {
        println!(
            "Dropshit TUI: стрелки — регион, пробел — блокировка, a — применить, u — снять, s — проверить правила, p/r — HTTPS-замер, c — постоянный замер, R — обновить список, q — выход. Требуются curl, iproute2 и терминал."
        );
        return Ok(());
    }
    let _terminal = Terminal::enter()?;
    let (tx, rx) = mpsc::channel();
    let mut app = App::new(tx);
    app.fetch();
    let mut last_flow_check = Instant::now() - Duration::from_secs(10);
    loop {
        while let Ok(msg) = rx.try_recv() {
            app.event(msg)
        }
        app.tick();
        if last_flow_check.elapsed() >= Duration::from_secs(3) {
            app.flows = data::observe_udp(&app.regions);
            last_flow_check = Instant::now();
        }
        app.render(&mut io::stdout())?;
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Down | KeyCode::Char('j') => {
                        app.selected = (app.selected + 1).min(app.regions.len().saturating_sub(1))
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        app.selected = app.selected.saturating_sub(1)
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
