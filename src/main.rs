use actix_web::{
    App, HttpRequest, HttpResponse, HttpServer, Responder, get,
    http::header,
    web::{Data, Path, Query},
};
use anyhow::{Result, anyhow};
use chrono::{FixedOffset, Local, TimeZone, Utc};
use clap::Parser;
use log::{debug, warn};
use reqwest::Client;
use std::{
    collections::BTreeMap,
    io::{BufWriter, Cursor},
    net::SocketAddrV4,
    process::exit,
    str::FromStr,
    sync::{Mutex, OnceLock, RwLock},
};
use xml::{
    EventReader,
    reader::XmlEvent as XmlReadEvent,
    writer::{EmitterConfig, XmlEvent as XmlWriteEvent},
};

use tokio::task::JoinSet;

fn extract_token(req: &HttpRequest) -> Option<String> {
    if let Some(auth) = req.headers().get(header::AUTHORIZATION)
        && let Ok(auth_str) = auth.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        return Some(token.to_string());
    }
    if let Some(token) = req
        .headers()
        .get("X-Api-Token")
        .and_then(|v| v.to_str().ok())
    {
        return Some(token.to_string());
    }
    if let Some(query) = req.uri().query() {
        for part in query.split('&') {
            let mut kv = part.splitn(2, '=');
            let key = kv.next().unwrap_or("");
            if key == "token" {
                let value = kv.next().unwrap_or("");
                return Some(value.to_string());
            }
        }
    }
    None
}

fn check_auth(req: &HttpRequest, config: &Config, endpoint: &str) -> bool {
    if !should_protect(config, endpoint) {
        return true;
    }
    if config.auth.token.is_empty() {
        return true;
    }
    let token = extract_token(req).unwrap_or_default();
    token == config.auth.token
}

mod args;
use args::{Args, EffectiveArgs};

mod iptv;
use iptv::{Channel, get_channels, get_icon};

mod proxy;

mod config;
use config::{
    CompiledConfig, Config, ManageTestResult, build_templates, compile_config, load_config,
    should_protect,
};

mod playlist;
use playlist::{
    ChannelEntry, EntryBuildContext, add_alias_and_resolution_for_name, apply_alias,
    finalize_entries, parse_m3u_playlist, render_playlist, resolve_group_for_alias,
};

static OLD_PLAYLIST: Mutex<Option<String>> = Mutex::new(None);
static OLD_XMLTV: Mutex<Option<String>> = Mutex::new(None);
static START_TIME: OnceLock<std::time::SystemTime> = OnceLock::new();

struct RuntimeConfig {
    config: Config,
    compiled: CompiledConfig,
    templates: handlebars::Handlebars<'static>,
}

struct AppState {
    args: EffectiveArgs,
    config_path: Option<String>,
    runtime: RwLock<RuntimeConfig>,
}

fn to_xmltv_time(unix_time: i64) -> Result<String> {
    match Utc.timestamp_millis_opt(unix_time) {
        chrono::LocalResult::Single(t) => Ok(t
            .with_timezone(&FixedOffset::east_opt(8 * 60 * 60).ok_or(anyhow!(""))?)
            .format("%Y%m%d%H%M%S")
            .to_string()),
        _ => Err(anyhow!("fail to parse time")),
    }
}

fn to_xmltv(channels: Vec<Channel>, extra: Vec<EventReader<Cursor<String>>>) -> Result<String> {
    let mut buf = BufWriter::new(Vec::new());
    let mut writer = EmitterConfig::new()
        .perform_indent(false)
        .create_writer(&mut buf);
    writer.write(
        XmlWriteEvent::start_element("tv")
            .attr("generator-info-name", "iptv-proxy")
            .attr("source-info-name", "iptv-proxy"),
    )?;
    for channel in channels.iter() {
        writer.write(
            XmlWriteEvent::start_element("channel").attr("id", &format!("{}", channel.id)),
        )?;
        writer.write(XmlWriteEvent::start_element("display-name"))?;
        writer.write(XmlWriteEvent::characters(&channel.name))?;
        writer.write(XmlWriteEvent::end_element())?;
        writer.write(XmlWriteEvent::end_element())?;
    }
    // For each extra xml reader, iterate its events and copy allowed tags
    for reader in extra {
        for e in reader {
            match e {
                Ok(XmlReadEvent::StartElement {
                    name, attributes, ..
                }) => {
                    let name = name.to_string();
                    let name = name.as_str();
                    if name != "channel"
                        && name != "display-name"
                        && name != "desc"
                        && name != "title"
                        && name != "sub-title"
                        && name != "programme"
                    {
                        continue;
                    }
                    let name = if name == "title" {
                        let mut iter = attributes.iter();
                        loop {
                            let attr = iter.next();
                            if attr.is_none() {
                                break "title";
                            }
                            let attr = attr.unwrap();
                            if attr.name.to_string() == "lang" && attr.value != "chi" {
                                break "title_extra";
                            }
                        }
                    } else {
                        name
                    };
                    let mut tag = XmlWriteEvent::start_element(name);
                    for attr in attributes.iter() {
                        tag = tag.attr(attr.name.borrow(), &attr.value);
                    }
                    writer.write(tag)?;
                }
                Ok(XmlReadEvent::Characters(content)) => {
                    writer.write(XmlWriteEvent::characters(&content))?;
                }
                Ok(XmlReadEvent::EndElement { name }) => {
                    let name = name.to_string();
                    let name = name.as_str();
                    if name != "channel"
                        && name != "display-name"
                        && name != "desc"
                        && name != "title"
                        && name != "sub-title"
                        && name != "programme"
                    {
                        continue;
                    }
                    writer.write(XmlWriteEvent::end_element())?;
                }
                _ => {}
            }
        }
    }
    for channel in channels.iter() {
        for epg in channel.epg.iter() {
            writer.write(
                XmlWriteEvent::start_element("programme")
                    .attr("start", &format!("{} +0800", to_xmltv_time(epg.start)?))
                    .attr("stop", &format!("{} +0800", to_xmltv_time(epg.stop)?))
                    .attr("channel", &format!("{}", channel.id)),
            )?;
            writer.write(XmlWriteEvent::start_element("title").attr("lang", "chi"))?;
            writer.write(XmlWriteEvent::characters(&epg.title))?;
            writer.write(XmlWriteEvent::end_element())?;
            if !epg.desc.is_empty() {
                writer.write(XmlWriteEvent::start_element("desc"))?;
                writer.write(XmlWriteEvent::characters(&epg.desc))?;
                writer.write(XmlWriteEvent::end_element())?;
            }
            writer.write(XmlWriteEvent::end_element())?;
        }
    }
    writer.write(XmlWriteEvent::end_element())?;
    Ok(String::from_utf8(buf.into_inner()?)?)
}

async fn parse_extra_xml(url: &str) -> Result<EventReader<Cursor<String>>> {
    let client = Client::builder().build()?;
    let url = reqwest::Url::parse(url)?;
    let response = client.get(url).send().await?.error_for_status()?;
    let xml = response.text().await?;
    let reader = Cursor::new(xml);
    Ok(EventReader::new(reader))
}

#[get("/xmltv")]
async fn xmltv(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    debug!("Get EPG");
    let (use_alias_name, need_auth) = match state.runtime.read() {
        Ok(guard) => (
            guard.config.xmltv.use_alias_name,
            check_auth(&req, &guard.config, "xmltv"),
        ),
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    if !need_auth {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let scheme = req.connection_info().scheme().to_owned();
    let host = req.connection_info().host().to_owned();
    // parse all extra xmltv URLs in parallel using JoinSet, collect successful readers
    let extra_readers = if !state.args.extra_xmltv.is_empty() {
        let mut set = JoinSet::new();
        for (i, u) in state.args.extra_xmltv.iter().enumerate() {
            let u = u.clone();
            set.spawn(async move { (i, parse_extra_xml(&u).await) });
        }
        let mut readers = Vec::new();
        while let Some(res) = set.join_next().await {
            match res {
                Ok((_, Ok(reader))) => readers.push(reader),
                Ok((i, Err(e))) => warn!(
                    "Failed to parse extra xmltv ({}): {}",
                    state.args.extra_xmltv[i], e
                ),
                Err(e) => warn!("Task join error parsing extra xmltv: {}", e),
            }
        }
        readers
    } else {
        Vec::new()
    };
    let xml = get_channels(&state.args, true, &scheme, &host)
        .await
        .and_then(|mut ch| {
            if use_alias_name {
                let runtime = match state.runtime.read() {
                    Ok(guard) => guard,
                    Err(_) => return Err(anyhow!("Config lock poisoned")),
                };
                for channel in ch.iter_mut() {
                    let alias = apply_alias(&channel.name, &runtime.config, &runtime.compiled);
                    let alias = alias.trim().to_string();
                    if !alias.is_empty() {
                        channel.name = alias;
                    }
                }
            }
            to_xmltv(ch, extra_readers)
        });
    match xml {
        Err(e) => {
            if let Some(old_xmltv) = OLD_XMLTV.try_lock().ok().and_then(|f| f.to_owned()) {
                HttpResponse::Ok().content_type("text/xml").body(old_xmltv)
            } else {
                HttpResponse::InternalServerError().body(format!("Error getting channels: {}", e))
            }
        }
        Ok(xml) => {
            if let Ok(mut old_xmltv) = OLD_XMLTV.try_lock() {
                *old_xmltv = Some(xml.clone());
            }
            HttpResponse::Ok().content_type("text/xml").body(xml)
        }
    }
}

async fn parse_extra_playlist(url: &str) -> Result<String> {
    let client = Client::builder().build()?;
    let url = reqwest::Url::parse(url)?;
    let response = client.get(url).send().await?.error_for_status()?;
    let response = response.text().await?;
    if response.starts_with("#EXTM3U") {
        response
            .find('\n')
            .map(|i| response[i..].to_owned()) // include \n
            .ok_or(anyhow!("Empty playlist"))
    } else {
        Err(anyhow!("Playlist does not start with #EXTM3U"))
    }
}

#[get("/logo/{id}.png")]
async fn logo(state: Data<AppState>, path: Path<String>) -> impl Responder {
    debug!("Get logo");
    match get_icon(&state.args, &path).await {
        Ok(icon) => HttpResponse::Ok().content_type("image/png").body(icon),
        Err(e) => HttpResponse::NotFound().body(format!("Error getting channels: {}", e)),
    }
}

fn merge_arg(opt: Option<String>, fallback: Option<String>, default: &str) -> String {
    opt.or(fallback).unwrap_or_else(|| default.to_string())
}

fn merge_opt(opt: Option<String>, fallback: Option<String>) -> Option<String> {
    opt.or(fallback)
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn build_effective_args(args: &Args, config: &Config) -> Result<EffectiveArgs> {
    let app = &config.app;
    let user = args.user.clone().or(app.user.clone());
    let passwd = args.passwd.clone().or(app.passwd.clone());
    let mac = args.mac.clone().or(app.mac.clone());
    if user.is_none() || passwd.is_none() || mac.is_none() {
        return Err(anyhow!(
            "Missing user/passwd/mac. Provide via CLI or config [app]."
        ));
    }
    Ok(EffectiveArgs {
        user: user.unwrap(),
        passwd: passwd.unwrap(),
        mac: mac.unwrap(),
        imei: merge_arg(args.imei.clone(), app.imei.clone(), ""),
        bind: merge_arg(args.bind.clone(), app.bind.clone(), "0.0.0.0:7878"),
        address: merge_arg(args.address.clone(), app.address.clone(), ""),
        interface: merge_opt(args.interface.clone(), app.interface.clone()),
        extra_playlist: args.extra_playlist.clone(),
        extra_xmltv: args.extra_xmltv.clone(),
        udp_proxy: args.udp_proxy || app.udp_proxy,
        rtsp_proxy: args.rtsp_proxy || app.rtsp_proxy,
    })
}

fn build_local_entries(
    channels: Vec<Channel>,
    args: &EffectiveArgs,
    scheme: &str,
    host: &str,
    playseek: &str,
    start_index: usize,
) -> Vec<ChannelEntry> {
    let mut entries = Vec::new();
    let mut index = start_index;
    for c in channels.into_iter() {
        let url = if args.udp_proxy {
            c.igmp.clone().unwrap_or_else(|| c.rtsp.clone())
        } else {
            c.rtsp.clone()
        };
        let (catchup, catchup_source, catchup_attr) = if let Some(url) = c.time_shift_url.as_ref() {
            let source = format!("{}&playseek={}", url, playseek);
            let attr = format!(
                r#" catchup="default" catchup-source="{}&playseek={}" "#,
                url, playseek
            );
            ("default".to_string(), source, attr)
        } else {
            (String::new(), String::new(), String::new())
        };
        let entry = ChannelEntry {
            key: format!("gd:{}:{}", c.id, index),
            source: String::from("gd-iptv"),
            channel_id: Some(c.id),
            url,
            raw_name: c.name.clone(),
            alias_name: String::new(),
            group: String::new(),
            tvg_id: c.id.to_string(),
            tvg_name: c.name.clone(),
            tvg_logo: format!("{scheme}://{host}/logo/{}.png", c.id),
            tvg_chno: c.id.to_string(),
            catchup,
            catchup_source,
            catchup_attr,
            extras: BTreeMap::new(),
            resolution_score: 0,
            resolution_label: "Unknown".to_string(),
            original_index: index,
        };
        entries.push(entry);
        index += 1;
    }
    entries
}

#[get("/playlist")]
async fn playlist_handler(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    debug!("Get playlist");
    let need_auth = match state.runtime.read() {
        Ok(guard) => check_auth(&req, &guard.config, "playlist"),
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    if !need_auth {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let scheme = req.connection_info().scheme().to_owned();
    let host = req.connection_info().host().to_owned();
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Unknown");
    let playseek = if user_agent.to_lowercase().contains("kodi") {
        "{utc:YmdHMS}-{utcend:YmdHMS}"
    } else {
        "${(b)yyyyMMddHHmmss}-${(e)yyyyMMddHHmmss}"
    };
    match get_channels(&state.args, false, &scheme, &host).await {
        Err(e) => {
            if let Some(old_playlist) = OLD_PLAYLIST.try_lock().ok().and_then(|f| f.to_owned()) {
                HttpResponse::Ok()
                    .content_type("application/vnd.apple.mpegurl")
                    .body(old_playlist)
            } else {
                HttpResponse::InternalServerError().body(format!("Error getting channels: {}", e))
            }
        }
        Ok(ch) => {
            let mut entries = build_local_entries(ch, &state.args, &scheme, &host, playseek, 0);
            if !state.args.extra_playlist.is_empty() {
                let mut set = JoinSet::new();
                for (i, u) in state.args.extra_playlist.iter().enumerate() {
                    let u = u.clone();
                    set.spawn(async move { (i, parse_extra_playlist(&u).await) });
                }
                let mut index = entries.len();
                while let Some(res) = set.join_next().await {
                    match res {
                        Ok((i, Ok(s))) => {
                            let source = format!("extra:{}", i);
                            let mut extra_entries = parse_m3u_playlist(&s, &source, index);
                            index += extra_entries.len();
                            entries.append(&mut extra_entries);
                        }
                        Ok((i, Err(e))) => warn!(
                            "Failed to parse extra playlist ({}): {}",
                            state.args.extra_playlist[i], e
                        ),
                        Err(e) => warn!("Task join error parsing extra playlist: {}", e),
                    }
                }
            }

            let runtime = match state.runtime.read() {
                Ok(guard) => guard,
                Err(_) => {
                    return HttpResponse::InternalServerError().body("Config lock poisoned");
                }
            };
            let ctx = EntryBuildContext {
                config: &runtime.config,
                compiled: &runtime.compiled,
            };
            let entries = finalize_entries(entries, &ctx);
            let playlist = match render_playlist(&entries, &runtime.templates) {
                Ok(playlist) => playlist,
                Err(e) => {
                    return HttpResponse::InternalServerError()
                        .body(format!("Template render error: {}", e));
                }
            };
            if let Ok(mut old_playlist) = OLD_PLAYLIST.try_lock() {
                *old_playlist = Some(playlist.clone());
            }
            HttpResponse::Ok()
                .content_type("application/vnd.apple.mpegurl")
                .body(playlist)
        }
    }
}

#[get("/rtsp/{tail:.*}")]
async fn rtsp(
    state: Data<AppState>,
    params: Query<BTreeMap<String, String>>,
    req: HttpRequest,
) -> impl Responder {
    let path: String = req.match_info().query("tail").into();
    let mut param = req.query_string().to_string();
    if !params.contains_key("playseek") && params.contains_key("utc") {
        let start = params
            .get("utc")
            .map(|utc| utc.parse::<i64>().expect("Invalid number") * 1000)
            .map(|utc| to_xmltv_time(utc).unwrap())
            .unwrap();
        let end = params
            .get("lutc")
            .map(|lutc| lutc.parse::<i64>().expect("Invalid number") * 1000)
            .map(|lutc| to_xmltv_time(lutc).unwrap())
            .unwrap_or(to_xmltv_time(Local::now().timestamp_millis()).unwrap());
        param = format!("{}&playseek={}-{}", param, start, end);
    }
    HttpResponse::Ok().streaming(proxy::rtsp(
        format!("rtsp://{}?{}", path, param),
        state.args.interface.clone(),
    ))
}

#[get("/manage/config")]
async fn manage_config(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    let runtime = match state.runtime.read() {
        Ok(guard) => guard,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Config lock poisoned");
        }
    };
    if !runtime.config.manage.enabled {
        return HttpResponse::NotFound().body("Manage disabled");
    }
    if !check_auth(&req, &runtime.config, "manage") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let mut safe = runtime.config.clone();
    if !safe.app.user.is_none() {
        safe.app.user = Some("REDACTED".to_string());
    }
    if !safe.app.passwd.is_none() {
        safe.app.passwd = Some("REDACTED".to_string());
    }
    if !safe.app.mac.is_none() {
        safe.app.mac = Some("REDACTED".to_string());
    }
    if !safe.auth.token.is_empty() {
        safe.auth.token = "REDACTED".to_string();
    }
    match toml::to_string_pretty(&safe) {
        Ok(text) => HttpResponse::Ok()
            .content_type("text/plain; charset=utf-8")
            .body(text),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

#[get("/manage")]
async fn manage_index(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    let runtime = match state.runtime.read() {
        Ok(guard) => guard,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Config lock poisoned");
        }
    };
    if !runtime.config.manage.enabled {
        return HttpResponse::NotFound().body("Manage disabled");
    }
    if !check_auth(&req, &runtime.config, "manage") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let start = START_TIME
        .get()
        .cloned()
        .unwrap_or(std::time::SystemTime::now());
    let uptime = start.elapsed().map(|d| d.as_secs()).unwrap_or(0);
    let token = extract_token(&req).unwrap_or_default();
    let token_q = if token.is_empty() {
        String::new()
    } else {
        format!("?token={}", token)
    };
    let token_tail = if token_q.is_empty() {
        String::new()
    } else {
        format!("&token={}", token)
    };
    let html = format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Manage Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
  <style>
    :root {{ --bs-body-bg: #f8f9fa; }}
    body {{ background-color: var(--bs-body-bg); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
    .navbar-brand {{ font-weight: 700; }}
    .card {{ border: none; border-radius: 12px; box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075); transition: transform 0.2s; }}
    .card:hover {{ transform: translateY(-3px); }}
    .action-icon {{ width: 48px; height: 48px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 24px; margin-bottom: 1rem; }}
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
    <div class="container">
      <a class="navbar-brand" href="/status{token_q}"><i class="bi bi-broadcast me-2"></i>IPTV Proxy</a>
      <div class="navbar-nav ms-auto">
        <a class="nav-link" href="/status{token_q}">Status</a>
        <a class="nav-link active" href="/manage{token_q}">Manage</a>
      </div>
    </div>
  </nav>
  <div class="container pb-5">
    <div class="row mb-4">
      <div class="col">
        <h2 class="fw-bold">Management Dashboard</h2>
        <p class="text-muted">Control and monitor your IPTV proxy settings.</p>
      </div>
    </div>
    
    <div class="row g-4 mb-5">
      <div class="col-lg-3 col-md-6">
        <div class="card h-100 p-4">
          <div class="action-icon bg-primary text-white"><i class="bi bi-file-earmark-code"></i></div>
          <h5 class="fw-bold">View Configuration</h5>
          <p class="small text-muted flex-grow-1">Inspect the current active TOML configuration and runtime parameters.</p>
          <a href="/manage/config{token_q}" class="btn btn-outline-primary btn-sm mt-3">Open Config</a>
        </div>
      </div>
      <div class="col-lg-3 col-md-6">
        <div class="card h-100 p-4">
          <div class="action-icon bg-success text-white"><i class="bi bi-arrow-clockwise"></i></div>
          <h5 class="fw-bold">Hot Reload</h5>
          <p class="small text-muted flex-grow-1">Reload the configuration file from disk without restarting the service.</p>
          <a href="/manage/reload{token_q}" class="btn btn-outline-success btn-sm mt-3">Reload Now</a>
        </div>
      </div>
      <div class="col-lg-3 col-md-6">
        <div class="card h-100 p-4">
          <div class="action-icon bg-info text-white"><i class="bi bi-search"></i></div>
          <h5 class="fw-bold">Test Rules</h5>
          <p class="small text-muted flex-grow-1">Verify alias and grouping rules against specific channel names.</p>
          <a href="/manage/test?name=CCTV1{token_tail}" class="btn btn-outline-info btn-sm mt-3">Try Example</a>
        </div>
      </div>
      <div class="col-lg-3 col-md-6">
        <div class="card h-100 p-4">
          <div class="action-icon bg-warning text-dark"><i class="bi bi-list-stars"></i></div>
          <h5 class="fw-bold">Channel List</h5>
          <p class="small text-muted flex-grow-1">Browse all discovered channels with applied alias and resolution info.</p>
          <div class="d-flex gap-2 mt-3">
            <a href="/manage/channels/html?limit=200{token_tail}" class="btn btn-warning btn-sm">Interactive UI</a>
            <a href="/manage/channels?limit=200{token_tail}" class="btn btn-outline-warning btn-sm">JSON</a>
          </div>
        </div>
      </div>
    </div>

    <div class="card bg-white p-4">
      <h5 class="mb-4 fw-bold"><i class="bi bi-info-circle me-2"></i>Runtime Summary</h5>
      <div class="row g-4 text-center">
        <div class="col-sm-4">
          <div class="border-end">
            <div class="text-muted small text-uppercase fw-bold mb-1">Uptime</div>
            <div class="fw-bold h4 mb-0 text-primary">{uptime}s</div>
          </div>
        </div>
        <div class="col-sm-4">
          <div class="border-end">
            <div class="text-muted small text-uppercase fw-bold mb-1">Alias Rules</div>
            <div class="fw-bold h4 mb-0 text-primary">{alias_rules}</div>
          </div>
        </div>
        <div class="col-sm-4">
          <div>
            <div class="text-muted small text-uppercase fw-bold mb-1">Groups</div>
            <div class="fw-bold h4 mb-0 text-primary">{group_count}</div>
          </div>
        </div>
      </div>
    </div>

    <div class="mt-5 p-4 bg-light rounded-3 border">
      <h6 class="fw-bold mb-2">Access Tip</h6>
      <p class="small text-muted mb-0">If security tokens are enabled, ensure you append <code>?token=YOUR_TOKEN</code> to all management URLs or include it in the request headers.</p>
    </div>
  </div>
</body>
</html>"#,
        uptime = uptime,
        alias_rules = runtime.config.alias.rules.len(),
        group_count = runtime.config.groups.entries.len(),
        token_q = token_q,
        token_tail = token_tail,
    );
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

#[get("/manage/reload")]
async fn manage_reload(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    let current = match state.runtime.read() {
        Ok(guard) => guard,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Config lock poisoned");
        }
    };
    if !current.config.manage.enabled {
        return HttpResponse::NotFound().body("Manage disabled");
    }
    if !check_auth(&req, &current.config, "manage") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    drop(current);

    let path = match state.config_path.as_ref() {
        Some(path) => path.clone(),
        None => {
            return HttpResponse::BadRequest().body("No config path specified");
        }
    };
    let config = match load_config(Some(&path)) {
        Ok(cfg) => cfg,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    let compiled = match compile_config(&config) {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    let templates = match build_templates(&config) {
        Ok(t) => t,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    let mut runtime = match state.runtime.write() {
        Ok(guard) => guard,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Config lock poisoned");
        }
    };
    runtime.config = config;
    runtime.compiled = compiled;
    runtime.templates = templates;
    HttpResponse::Ok().body("OK")
}

#[get("/manage/test")]
async fn manage_test(
    state: Data<AppState>,
    req: HttpRequest,
    params: Query<BTreeMap<String, String>>,
) -> impl Responder {
    let runtime = match state.runtime.read() {
        Ok(guard) => guard,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Config lock poisoned");
        }
    };
    if !runtime.config.manage.enabled {
        return HttpResponse::NotFound().body("Manage disabled");
    }
    if !check_auth(&req, &runtime.config, "manage") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let name = match params.get("name") {
        Some(v) => v.to_string(),
        None => return HttpResponse::BadRequest().body("Missing name"),
    };
    let ctx = EntryBuildContext {
        config: &runtime.config,
        compiled: &runtime.compiled,
    };
    let (alias, score, label) = add_alias_and_resolution_for_name(&name, &ctx);
    let group = resolve_group_for_alias(
        &alias,
        &runtime.compiled,
        &runtime.config.groups.default_group,
    );
    let res = ManageTestResult {
        input: name,
        alias_name: alias,
        resolution_score: score,
        resolution_label: label,
        group,
    };
    match serde_json::to_string_pretty(&res) {
        Ok(text) => HttpResponse::Ok()
            .content_type("application/json")
            .body(text),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

#[get("/manage/channels")]
async fn manage_channels(
    state: Data<AppState>,
    req: HttpRequest,
    params: Query<BTreeMap<String, String>>,
) -> impl Responder {
    let (enabled, need_auth) = match state.runtime.read() {
        Ok(guard) => (
            guard.config.manage.enabled,
            check_auth(&req, &guard.config, "manage"),
        ),
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    if !enabled {
        return HttpResponse::NotFound().body("Manage disabled");
    }
    if !need_auth {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let scheme = req.connection_info().scheme().to_owned();
    let host = req.connection_info().host().to_owned();
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Unknown");
    let playseek = if user_agent.to_lowercase().contains("kodi") {
        "{utc:YmdHMS}-{utcend:YmdHMS}"
    } else {
        "${(b)yyyyMMddHHmmss}-${(e)yyyyMMddHHmmss}"
    };
    let channels = match get_channels(&state.args, false, &scheme, &host).await {
        Ok(ch) => ch,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    let mut entries = build_local_entries(channels, &state.args, &scheme, &host, playseek, 0);
    if !state.args.extra_playlist.is_empty() {
        let mut set = JoinSet::new();
        for (i, u) in state.args.extra_playlist.iter().enumerate() {
            let u = u.clone();
            set.spawn(async move { (i, parse_extra_playlist(&u).await) });
        }
        let mut index = entries.len();
        while let Some(res) = set.join_next().await {
            match res {
                Ok((i, Ok(s))) => {
                    let source = format!("extra:{}", i);
                    let mut extra_entries = parse_m3u_playlist(&s, &source, index);
                    index += extra_entries.len();
                    entries.append(&mut extra_entries);
                }
                Ok((i, Err(e))) => warn!(
                    "Failed to parse extra playlist ({}): {}",
                    state.args.extra_playlist[i], e
                ),
                Err(e) => warn!("Task join error parsing extra playlist: {}", e),
            }
        }
    }
    let runtime = match state.runtime.read() {
        Ok(guard) => guard,
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    let ctx = EntryBuildContext {
        config: &runtime.config,
        compiled: &runtime.compiled,
    };
    let mut entries = finalize_entries(entries, &ctx);
    if let Some(limit) = params.get("limit").and_then(|v| v.parse::<usize>().ok())
        && entries.len() > limit
    {
        entries.truncate(limit);
    }
    match serde_json::to_string_pretty(&entries) {
        Ok(text) => HttpResponse::Ok()
            .content_type("application/json")
            .body(text),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

#[get("/manage/channels/html")]
async fn manage_channels_html(
    state: Data<AppState>,
    req: HttpRequest,
    params: Query<BTreeMap<String, String>>,
) -> impl Responder {
    let (enabled, need_auth) = match state.runtime.read() {
        Ok(guard) => (
            guard.config.manage.enabled,
            check_auth(&req, &guard.config, "manage"),
        ),
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    if !enabled {
        return HttpResponse::NotFound().body("Manage disabled");
    }
    if !need_auth {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let scheme = req.connection_info().scheme().to_owned();
    let host = req.connection_info().host().to_owned();
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Unknown");
    let playseek = if user_agent.to_lowercase().contains("kodi") {
        "{utc:YmdHMS}-{utcend:YmdHMS}"
    } else {
        "${(b)yyyyMMddHHmmss}-${(e)yyyyMMddHHmmss}"
    };
    let channels = match get_channels(&state.args, false, &scheme, &host).await {
        Ok(ch) => ch,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };
    let mut entries = build_local_entries(channels, &state.args, &scheme, &host, playseek, 0);
    if !state.args.extra_playlist.is_empty() {
        let mut set = JoinSet::new();
        for (i, u) in state.args.extra_playlist.iter().enumerate() {
            let u = u.clone();
            set.spawn(async move { (i, parse_extra_playlist(&u).await) });
        }
        let mut index = entries.len();
        while let Some(res) = set.join_next().await {
            match res {
                Ok((i, Ok(s))) => {
                    let source = format!("extra:{}", i);
                    let mut extra_entries = parse_m3u_playlist(&s, &source, index);
                    index += extra_entries.len();
                    entries.append(&mut extra_entries);
                }
                Ok((i, Err(e))) => warn!(
                    "Failed to parse extra playlist ({}): {}",
                    state.args.extra_playlist[i], e
                ),
                Err(e) => warn!("Task join error parsing extra playlist: {}", e),
            }
        }
    }
    let runtime = match state.runtime.read() {
        Ok(guard) => guard,
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    let ctx = EntryBuildContext {
        config: &runtime.config,
        compiled: &runtime.compiled,
    };
    let mut entries = finalize_entries(entries, &ctx);
    if let Some(limit) = params.get("limit").and_then(|v| v.parse::<usize>().ok())
        && entries.len() > limit
    {
        entries.truncate(limit);
    }

    let token = extract_token(&req).unwrap_or_default();
    let token_q = if token.is_empty() {
        String::new()
    } else {
        format!("?token={}", token)
    };
    let _token_tail = if token_q.is_empty() {
        String::new()
    } else {
        format!("&token={}", token)
    };

    let count = entries.len();
    let limit = params.get("limit").and_then(|v| v.parse::<usize>().ok()).unwrap_or(entries.len());
    
    let rows = entries
        .iter()
        .map(|e| {
            format!(
                "<tr><td class='fw-bold text-primary'>{}</td><td class='text-muted small'>{}</td><td><span class='badge bg-light text-dark border'>{}</span></td><td><span class='badge bg-info-subtle text-info border border-info-subtle'>{}</span></td><td class='url-cell text-truncate' style='max-width:250px;'><a href='{}' class='text-decoration-none small' title='{}'>{}</a></td></tr>",
                html_escape(&e.alias_name),
                html_escape(&e.raw_name),
                html_escape(&e.group),
                html_escape(&e.resolution_label),
                html_escape(&e.url),
                html_escape(&e.url),
                html_escape(&e.url),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let html = format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Channel List - IPTV Proxy</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
  <style>
    :root {{ --bs-body-bg: #f8f9fa; }}
    body {{ background-color: var(--bs-body-bg); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
    .navbar-brand {{ font-weight: 700; }}
    .card {{ border: none; border-radius: 12px; box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075); }}
    .table thead th {{ background-color: #f8f9fa; border-top: none; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; color: #6c757d; padding: 12px 16px; }}
    .table td {{ vertical-align: middle; padding: 12px 16px; font-size: 0.9rem; }}
    .search-wrap {{ position: relative; }}
    .search-wrap i {{ position: absolute; left: 12px; top: 50%; transform: translateY(-50%); color: #6c757d; }}
    .search-wrap input {{ padding-left: 36px; border-radius: 10px; border-color: #e3e7ef; }}
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
    <div class="container">
      <a class="navbar-brand" href="/status{token_q}"><i class="bi bi-broadcast me-2"></i>IPTV Proxy</a>
      <div class="navbar-nav ms-auto">
        <a class="nav-link" href="/status{token_q}">Status</a>
        <a class="nav-link active" href="/manage{token_q}">Manage</a>
      </div>
    </div>
  </nav>
  <div class="container pb-5">
    <div class="row align-items-center mb-4 g-3">
      <div class="col-md-6">
        <h2 class="fw-bold mb-0">Channels</h2>
        <p class="text-muted mb-0 small">Browsing {count} discovered channels</p>
      </div>
      <div class="col-md-6">
        <div class="search-wrap">
          <i class="bi bi-search"></i>
          <input type="text" id="searchInput" class="form-control" placeholder="Search by name, alias or group...">
        </div>
      </div>
    </div>

    <div class="card overflow-hidden">
      <div class="table-responsive">
        <table class="table table-hover mb-0" id="channelTable">
          <thead>
            <tr>
              <th>Alias Name</th>
              <th>Original Name</th>
              <th>Group</th>
              <th>Res</th>
              <th>URL / Source</th>
            </tr>
          </thead>
          <tbody>
            {rows}
          </tbody>
        </table>
      </div>
    </div>
    
    <div class="mt-4 d-flex justify-content-between align-items-center">
      <div class="small text-muted">
        Showing up to {limit} entries. Use <code>?limit=N</code> to change.
      </div>
      <div>
        <a href="/manage/channels{token_q}" class="btn btn-outline-secondary btn-sm"><i class="bi bi-filetype-json me-1"></i>Export JSON</a>
      </div>
    </div>
  </div>

  <script>
    document.getElementById('searchInput').addEventListener('keyup', function() {{
      const searchText = this.value.toLowerCase();
      const rows = document.querySelectorAll('#channelTable tbody tr');
      
      rows.forEach(row => {{
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(searchText) ? '' : 'none';
      }});
    }});
  </script>
</body>
</html>"#,
        rows = rows,
        count = count,
        limit = limit,
        token_q = token_q,
    );
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

#[get("/status")]
async fn status(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    let need_auth = match state.runtime.read() {
        Ok(guard) => check_auth(&req, &guard.config, "status"),
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    if !need_auth {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let start = START_TIME
        .get()
        .cloned()
        .unwrap_or(std::time::SystemTime::now());
    let uptime = start.elapsed().map(|d| d.as_secs()).unwrap_or(0);

    let token = extract_token(&req).unwrap_or_default();
    let token_q = if token.is_empty() {
        String::new()
    } else {
        format!("?token={}", token)
    };
    let token_tail = if token.is_empty() {
        String::new()
    } else {
        format!("&token={}", token)
    };
    let channels_link = format!("/manage/channels?limit=200{token_tail}");

    let (
        alias_preview,
        group_pills,
        group_count,
        alias_rules,
        protected,
        token_set,
        manage_enabled,
        config_path,
    ) = match state.runtime.read() {
        Ok(guard) => {
            let alias_preview = guard
                .config
                .alias
                .rules
                .iter()
                .take(10)
                .enumerate()
                .map(|(i, r)| {
                    format!(
                        "<div class='mb-2 d-flex align-items-center'><span class='badge bg-light text-dark me-2'>{}</span> <code class='text-truncate'>{}</code> <i class='bi bi-arrow-right mx-2 text-muted'></i> <code class='text-truncate'>{}</code></div>",
                        i + 1,
                        html_escape(&r.pattern),
                        html_escape(&r.replace)
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let group_pills = guard
                .config
                .groups
                .entries
                .iter()
                .map(|g| {
                    format!(
                        "<span class='badge bg-primary-subtle text-primary border border-primary-subtle me-1 mb-1'>{}</span>",
                        html_escape(&g.group)
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            (
                alias_preview,
                group_pills,
                guard.config.groups.entries.len(),
                guard.config.alias.rules.len(),
                if guard.config.auth.protect.is_empty() {
                    String::from("none")
                } else {
                    guard.config.auth.protect.join(", ")
                },
                if guard.config.auth.token.is_empty() {
                    "no"
                } else {
                    "yes"
                },
                if guard.config.manage.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
                state
                    .config_path
                    .clone()
                    .unwrap_or_else(|| "default".to_string()),
            )
        }
        Err(_) => return HttpResponse::InternalServerError().body("Config lock poisoned"),
    };
    let scheme = req.connection_info().scheme().to_owned();
    let host = req.connection_info().host().to_owned();
    let channels_count = match get_channels(&state.args, false, &scheme, &host).await {
        Ok(ch) => ch.len(),
        Err(_) => 0,
    };
    let html = format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IPTV Proxy Status</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
  <style>
    :root {{ --bs-body-bg: #f8f9fa; }}
    body {{ background-color: var(--bs-body-bg); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
    .navbar-brand {{ font-weight: 700; }}
    .card {{ border: none; border-radius: 12px; box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075); }}
    .stat-icon {{ width: 40px; height: 40px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 20px; }}
    .bg-primary-light {{ background-color: rgba(13, 110, 253, 0.1); color: #0d6efd; }}
    .bg-success-light {{ background-color: rgba(25, 135, 84, 0.1); color: #198754; }}
    .bg-info-light {{ background-color: rgba(13, 202, 240, 0.1); color: #0dcaf0; }}
    .bg-warning-light {{ background-color: rgba(255, 193, 7, 0.1); color: #ffc107; }}
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
    <div class="container">
      <a class="navbar-brand" href="/status{token_q}"><i class="bi bi-broadcast me-2"></i>IPTV Proxy</a>
      <div class="navbar-nav ms-auto">
        <a class="nav-link active" href="/status{token_q}">Status</a>
        <a class="nav-link" href="/manage{token_q}">Manage</a>
      </div>
    </div>
  </nav>
  <div class="container pb-5">
    <div class="row g-3 mb-4">
      <div class="col-md-3">
        <div class="card p-3 h-100">
          <div class="d-flex align-items-center mb-2">
            <div class="stat-icon bg-success-light me-3"><i class="bi bi-cpu"></i></div>
            <div class="text-muted small text-uppercase fw-bold">System</div>
          </div>
          <div class="h4 mb-1">Running</div>
          <div class="small text-success">Uptime: {uptime}s</div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="card p-3 h-100">
          <div class="d-flex align-items-center mb-2">
            <div class="stat-icon bg-primary-light me-3"><i class="bi bi-tv"></i></div>
            <div class="text-muted small text-uppercase fw-bold">Channels</div>
          </div>
          <div class="h4 mb-1">{channels_count}</div>
          <div class="small"><a href="{channels_link}" class="text-decoration-none">Explore All <i class="bi bi-arrow-right"></i></a></div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="card p-3 h-100">
          <div class="d-flex align-items-center mb-2">
            <div class="stat-icon bg-info-light me-3"><i class="bi bi-shield-lock"></i></div>
            <div class="text-muted small text-uppercase fw-bold">Auth</div>
          </div>
          <div class="h4 mb-1">{token_set}</div>
          <div class="small text-muted text-truncate" title="{protected}">Protect: {protected}</div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="card p-3 h-100">
          <div class="d-flex align-items-center mb-2">
            <div class="stat-icon bg-warning-light me-3"><i class="bi bi-gear"></i></div>
            <div class="text-muted small text-uppercase fw-bold">Config</div>
          </div>
          <div class="h4 mb-1">{manage_enabled}</div>
          <div class="small text-muted text-truncate" title="{config_path}">{config_path}</div>
        </div>
      </div>
    </div>

    <div class="row g-4">
      <div class="col-lg-8">
        <div class="card mb-4">
          <div class="card-header bg-white py-3"><h5 class="mb-0">Functional Endpoints</h5></div>
          <div class="card-body">
            <div class="list-group list-group-flush">
              <a href="/playlist{token_q}" class="list-group-item list-group-item-action d-flex justify-content-between align-items-center px-0 py-3">
                <div><div class="fw-bold">M3U Playlist</div><div class="small text-muted">Aggregated playlist with alias and sorting</div></div>
                <span class="badge bg-primary rounded-pill">/playlist</span>
              </a>
              <a href="/xmltv{token_q}" class="list-group-item list-group-item-action d-flex justify-content-between align-items-center px-0 py-3">
                <div><div class="fw-bold">XMLTV EPG</div><div class="small text-muted">Electronic Program Guide data</div></div>
                <span class="badge bg-primary rounded-pill">/xmltv</span>
              </a>
              <div class="list-group-item d-flex justify-content-between align-items-center px-0 py-3">
                <div><div class="fw-bold">Extra Sources</div><div class="small text-muted">Additional M3U/XMLTV from CLI args</div></div>
                <div>
                  <span class="badge bg-secondary me-1">{extra_playlist} Playlists</span>
                  <span class="badge bg-secondary">{extra_xmltv} EPGs</span>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div class="card">
          <div class="card-header bg-white py-3"><h5 class="mb-0">Alias Rules Preview <span class="badge bg-light text-muted fw-normal ms-2">{alias_rules} total</span></h5></div>
          <div class="card-body">
            <div class="small">{alias_preview}</div>
          </div>
        </div>
      </div>
      <div class="col-lg-4">
        <div class="card mb-4">
          <div class="card-header bg-white py-3"><h5 class="mb-0">Channel Groups <span class="badge bg-light text-muted fw-normal ms-2">{group_count} total</span></h5></div>
          <div class="card-body">
            <div class="d-flex flex-wrap">{group_pills}</div>
          </div>
        </div>
        <div class="card">
          <div class="card-header bg-white py-3"><h5 class="mb-0">Quick Links</h5></div>
          <div class="card-body">
            <ul class="list-unstyled mb-0">
              <li class="mb-2"><a href="/manage{token_q}" class="text-decoration-none"><i class="bi bi-speedometer2 me-2"></i>Management Dashboard</a></li>
              <li class="mb-2"><a href="/manage/config{token_q}" class="text-decoration-none"><i class="bi bi-file-earmark-code me-2"></i>View Raw Config</a></li>
              <li><a href="/manage/channels/html{token_q}" class="text-decoration-none"><i class="bi bi-list-ul me-2"></i>Interactive Channel List</a></li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  </div>
</body>
</html>"#,
        uptime = uptime,
        config_path = config_path,
        manage_enabled = manage_enabled,
        protected = protected,
        token_set = if token_set == "yes" { "Active" } else { "None" },
        extra_playlist = state.args.extra_playlist.len(),
        extra_xmltv = state.args.extra_xmltv.len(),
        channels_count = channels_count,
        alias_rules = alias_rules,
        alias_preview = alias_preview,
        group_pills = group_pills,
        group_count = group_count,
        channels_link = channels_link,
        token_q = token_q,
    );
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

#[get("/udp/{addr}")]
async fn udp(state: Data<AppState>, addr: Path<String>) -> impl Responder {
    let addr = &*addr;
    let addr = match SocketAddrV4::from_str(addr) {
        Ok(addr) => addr,
        Err(e) => return HttpResponse::BadRequest().body(format!("Error: {}", e)),
    };
    HttpResponse::Ok().streaming(proxy::udp(addr, state.args.interface.clone()))
}

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let _ = START_TIME.set(std::time::SystemTime::now());
    let args = Args::parse();

    let config = match load_config(args.config.as_deref()) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            exit(1);
        }
    };
    let compiled = match compile_config(&config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to compile config: {}", e);
            exit(1);
        }
    };
    let templates = match build_templates(&config) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to build templates: {}", e);
            exit(1);
        }
    };
    let effective_args = match build_effective_args(&args, &config) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{}", e);
            exit(1);
        }
    };

    let state = Data::new(AppState {
        args: effective_args.clone(),
        config_path: args.config.clone(),
        runtime: RwLock::new(RuntimeConfig {
            config,
            compiled,
            templates,
        }),
    });

    let bind_addr = effective_args.bind.clone();
    HttpServer::new(move || {
        App::new()
            .service(xmltv)
            .service(playlist_handler)
            .service(logo)
            .service(rtsp)
            .service(udp)
            .service(status)
            .service(manage_index)
            .service(manage_config)
            .service(manage_reload)
            .service(manage_test)
            .service(manage_channels)
            .service(manage_channels_html)
            .app_data(state.clone())
    })
    .bind(bind_addr)?
    .run()
    .await
}
