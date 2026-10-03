use ipnet::IpNet;
use serde_json::{Value, json};
use std::{
    io::Write,
    process::{Command, Stdio},
};

pub struct Reply {
    pub backend: String,
    pub selected_backend: String,
    pub networks: Vec<IpNet>,
    pub active: bool,
}

pub fn send(action: &str, networks: &[IpNet]) -> Result<Reply, String> {
    let mut child = Command::new("/usr/bin/pkexec")
        .arg("/usr/libexec/dropshit-helper")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let request = if action == "status" {
        json!({"action":"status"})
    } else {
        json!({"action":"apply", "networks": networks.iter().map(ToString::to_string).collect::<Vec<_>>()})
    };
    child
        .stdin
        .take()
        .ok_or("helper stdin unavailable")?
        .write_all(request.to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    let reply: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| format!("helper: {}", String::from_utf8_lossy(&output.stderr).trim()))?;
    if !output.status.success() {
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
    })
}
