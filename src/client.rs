use crate::networks::Policy;
use ipnet::IpNet;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Mutex, OnceLock},
};

struct Session {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}
static SESSION: OnceLock<Mutex<Option<Session>>> = OnceLock::new();

pub struct Reply {
    pub backend: String,
    pub selected_backend: String,
    pub networks: Vec<IpNet>,
    pub active: bool,
    pub strict: bool,
    pub region: Option<String>,
}

pub fn send(action: &str, networks: &[IpNet]) -> Result<Reply, String> {
    send_policy(
        action,
        &Policy {
            networks: networks.to_vec(),
            ..Policy::default()
        },
    )
}

pub fn send_policy(action: &str, policy: &Policy) -> Result<Reply, String> {
    let mut session = SESSION
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|e| e.to_string())?;
    if session
        .as_mut()
        .is_some_and(|s| !matches!(s.child.try_wait(), Ok(None)))
    {
        *session = None;
    }
    if session.is_none() {
        let mut child = Command::new("/usr/bin/pkexec")
            .arg("/usr/libexec/dropshit-helper")
            .arg("--session")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| e.to_string())?;
        let input = child.stdin.take().ok_or("helper stdin unavailable")?;
        let output = BufReader::new(child.stdout.take().ok_or("helper stdout unavailable")?);
        *session = Some(Session {
            child,
            input,
            output,
        });
    }
    let request = if action == "status" {
        json!({"action":"status"})
    } else {
        json!({"action":"apply", "mode":policy.mode(), "region":policy.region, "networks": policy.networks.iter().map(ToString::to_string).collect::<Vec<_>>()})
    };
    let exchange = (|| {
        let s = session.as_mut().unwrap();
        writeln!(s.input, "{request}").map_err(|e| e.to_string())?;
        s.input.flush().map_err(|e| e.to_string())?;
        let mut text = String::new();
        if s.output.read_line(&mut text).map_err(|e| e.to_string())? == 0 {
            return Err("helper session closed".into());
        }
        serde_json::from_str::<Value>(&text).map_err(|e| e.to_string())
    })();
    let reply = match exchange {
        Ok(reply) => reply,
        Err(e) => {
            *session = None;
            return Err(e);
        }
    };
    if reply.get("error").is_some() {
        return Err(reply["error"].as_str().unwrap_or("helper failed").into());
    }
    Ok(Reply {
        backend: reply["backend"].as_str().ok_or("missing backend")?.into(),
        selected_backend: reply["selected_backend"]
            .as_str()
            .unwrap_or_else(|| reply["backend"].as_str().unwrap_or("unknown"))
            .into(),
        networks: reply["networks"]
            .as_array()
            .ok_or("missing networks")?
            .iter()
            .map(|v| {
                v.as_str()
                    .ok_or("invalid network")?
                    .parse()
                    .map_err(|e| format!("{e}"))
            })
            .collect::<Result<_, String>>()?,
        active: reply["active"].as_bool().ok_or("missing active status")?,
        strict: reply["mode"].as_str() == Some("allowlist"),
        region: reply["region"].as_str().map(str::to_owned),
    })
}
