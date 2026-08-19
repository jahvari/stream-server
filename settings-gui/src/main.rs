#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use anyhow::{Context, Result};
use reqwest::Client;
use std::{path::PathBuf, sync::Arc};

fn main() -> Result<()> {
    let (server_url, token_path) = parse_arguments();
    let http_client = Client::builder()
        .build()
        .context("failed to create HTTP client")?;
    let mut connector = settings_gui::HttpConnector::new(http_client, server_url.clone());
    if server_url_has_ip_literal_loopback(&server_url) {
        let path = token_path.or_else(default_token_path);
        if let Some(path) = path {
            match std::fs::read(&path) {
                Ok(bytes) => {
                    let token =
                        settings_gui::parse_settings_control_token(&bytes).with_context(|| {
                            format!("invalid settings token file: {}", path.display())
                        })?;
                    connector = connector.with_settings_control_token(token)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to read settings token file: {}", path.display())
                    });
                }
            }
        }
    }
    let connector = Arc::new(connector);
    settings_gui::run(connector)
}

fn parse_arguments() -> (String, Option<PathBuf>) {
    let mut server_url = "http://127.0.0.1:11470".to_string();
    let mut token_path = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--server-url" {
            if let Some(value) = args.next() {
                server_url = trim_server_url(value);
            }
        } else if let Some(value) = arg.strip_prefix("--server-url=") {
            server_url = trim_server_url(value.to_string());
        } else if arg == "--settings-token-file" {
            token_path = args.next().map(PathBuf::from);
        } else if let Some(value) = arg.strip_prefix("--settings-token-file=") {
            token_path = Some(PathBuf::from(value));
        }
    }
    (server_url, token_path)
}

fn trim_server_url(value: String) -> String {
    value.trim_end_matches('/').to_string()
}

fn server_url_has_ip_literal_loopback(server_url: &str) -> bool {
    reqwest::Url::parse(server_url)
        .ok()
        .and_then(|url| url.host_str()?.parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback())
}

fn default_token_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("stremio-server").join("settings-control.token"))
}
