use actix_web::{
    get,
    http::header,
    web::{Data, Path, Query},
    App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use anyhow::{anyhow, Result};
use argh::FromArgs;
use chrono::{FixedOffset, Local, TimeZone, Utc};
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
    reader::XmlEvent as XmlReadEvent,
    writer::{EmitterConfig, XmlEvent as XmlWriteEvent},
    EventReader,
};

use tokio::task::JoinSet;

fn extract_token(req: &HttpRequest) -> Option<String> {
    if let Some(auth) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
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
use iptv::{get_channels, get_icon, Channel};

mod proxy;

mod config;
use config::{
    build_templates, compile_config, load_config, should_protect, CompiledConfig, Config,
    ManageTestResult,
};

mod playlist;
use playlist::{
    add_alias_and_resolution_for_name, apply_alias, finalize_entries, parse_m3u_playlist,
    render_playlist, resolve_group_for_alias, ChannelEntry, EntryBuildContext,
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
    let runtime = match state.runtime.read() {
        Ok(guard) => guard,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Config lock poisoned");
        }
    };
    if !check_auth(&req, &runtime.config, "xmltv") {
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
            if runtime.config.xmltv.use_alias_name {
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
        let (catchup, catchup_source, catchup_attr) = if let Some(url) = c.time_shift_url.as_ref()
        {
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
    let runtime = match state.runtime.read() {
        Ok(guard) => guard,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Config lock poisoned");
        }
    };
    if !check_auth(&req, &runtime.config, "playlist") {
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
            let mut entries = build_local_entries(
                ch,
                &state.args,
                &scheme,
                &host,
                playseek,
                0,
            );
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
                            let mut extra_entries =
                                parse_m3u_playlist(&s, &source, index);
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
    if !params.contains_key("playseek") {
        if params.contains_key("utc") {
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
    match toml::to_string_pretty(&runtime.config) {
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
    let start = START_TIME.get().cloned().unwrap_or(std::time::SystemTime::now());
    let uptime = start
        .elapsed()
        .map(|d| d.as_secs())
        .unwrap_or(0);
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
  <title>Manage</title>
  <style>
    body {{ margin: 0; font-family: "Source Serif 4","Noto Serif SC","Source Serif Pro",serif; background:#f6f7fb; color:#1a1f2b; }}
    .wrap {{ max-width: 860px; margin: 40px auto; padding: 0 16px; }}
    h1 {{ margin: 0 0 16px; }}
    .card {{ background:#fff; border:1px solid #e3e7ef; border-radius:12px; padding:16px; margin-bottom:16px; box-shadow: 0 10px 30px rgba(16,24,40,0.08); }}
    a {{ color:#2b7fff; text-decoration:none; }}
    code {{ background:#eef2ff; padding:2px 6px; border-radius:6px; }}
    ul {{ margin: 8px 0 0; padding-left: 18px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Manage</h1>
    <div class="card">
      <div>运行概览</div>
      <ul>
        <li>Uptime: {uptime}s</li>
        <li>Alias Rules: {alias_rules}</li>
        <li>Groups: {group_count}</li>
      </ul>
    </div>
    <div class="card">
      <div>常用入口</div>
      <ul>
        <li><a href="/manage/config{token_q}">/manage/config</a> - 当前配置（TOML）</li>
        <li><a href="/manage/reload{token_q}">/manage/reload</a> - 热加载配置</li>
        <li><a href="/manage/test?name=CCTV1{token_tail}">/manage/test?name=CCTV1</a> - 测试别名/分组</li>
        <li><a href="/manage/channels?limit=200{token_tail}">/manage/channels?limit=200</a> - 查看解析后的频道数据</li>
        <li><a href="/manage/channels/html?limit=200{token_tail}">/manage/channels/html?limit=200</a> - 频道列表（HTML）</li>
      </ul>
    </div>
    <div class="card">
      <div>提示</div>
      <div style="margin-top:8px;">如果启用了 token，请使用 <code>?token=xxx</code> 或 Header 访问。</div>
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
async fn manage_test(state: Data<AppState>, req: HttpRequest, params: Query<BTreeMap<String, String>>) -> impl Responder {
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
    let group = resolve_group_for_alias(&alias, &runtime.compiled, &runtime.config.groups.default_group);
    let res = ManageTestResult {
        input: name,
        alias_name: alias,
        resolution_score: score,
        resolution_label: label,
        group,
    };
    match serde_json::to_string_pretty(&res) {
        Ok(text) => HttpResponse::Ok().content_type("application/json").body(text),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

#[get("/manage/channels")]
async fn manage_channels(state: Data<AppState>, req: HttpRequest, params: Query<BTreeMap<String, String>>) -> impl Responder {
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
    let mut entries = build_local_entries(
        channels,
        &state.args,
        &scheme,
        &host,
        playseek,
        0,
    );
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
    let ctx = EntryBuildContext {
        config: &runtime.config,
        compiled: &runtime.compiled,
    };
    let mut entries = finalize_entries(entries, &ctx);
    if let Some(limit) = params.get("limit").and_then(|v| v.parse::<usize>().ok()) {
        if entries.len() > limit {
            entries.truncate(limit);
        }
    }
    match serde_json::to_string_pretty(&entries) {
        Ok(text) => HttpResponse::Ok().content_type("application/json").body(text),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

#[get("/manage/channels/html")]
async fn manage_channels_html(state: Data<AppState>, req: HttpRequest, params: Query<BTreeMap<String, String>>) -> impl Responder {
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
    let mut entries = build_local_entries(
        channels,
        &state.args,
        &scheme,
        &host,
        playseek,
        0,
    );
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
    let ctx = EntryBuildContext {
        config: &runtime.config,
        compiled: &runtime.compiled,
    };
    let mut entries = finalize_entries(entries, &ctx);
    if let Some(limit) = params.get("limit").and_then(|v| v.parse::<usize>().ok()) {
        if entries.len() > limit {
            entries.truncate(limit);
        }
    }

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

    let rows = entries
        .iter()
        .map(|e| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&e.alias_name),
                html_escape(&e.raw_name),
                html_escape(&e.group),
                html_escape(&e.resolution_label),
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
  <title>Channels</title>
  <style>
    body {{ margin:0; font-family:"Source Serif 4","Noto Serif SC","Source Serif Pro",serif; background:#f6f7fb; color:#1a1f2b; }}
    .wrap {{ max-width: 1100px; margin: 40px auto; padding: 0 16px; }}
    h1 {{ margin: 0 0 12px; }}
    a {{ color:#2b7fff; text-decoration:none; }}
    .toolbar {{ display:flex; gap:12px; align-items:center; margin-bottom:16px; }}
    .card {{ background:#fff; border:1px solid #e3e7ef; border-radius:12px; padding:16px; box-shadow: 0 10px 30px rgba(16,24,40,0.08); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align:left; padding: 10px; border-bottom:1px solid #eef1f6; font-size:14px; vertical-align:top; }}
    th {{ color:#5b6b7f; font-weight:600; text-transform:uppercase; font-size:12px; letter-spacing:0.4px; }}
    code {{ background:#eef2ff; padding:2px 6px; border-radius:6px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="toolbar">
      <h1>Channels</h1>
      <a href="/manage/channels{token_q}">JSON</a>
      <a href="/manage{token_q}">Manage</a>
    </div>
    <div class="card">
      <table>
        <thead>
          <tr>
            <th>Alias</th>
            <th>Raw</th>
            <th>Group</th>
            <th>Res</th>
            <th>URL</th>
          </tr>
        </thead>
        <tbody>
          {rows}
        </tbody>
      </table>
      <div style="margin-top:12px; color:#5b6b7f; font-size:12px;">使用 <code>?limit=200{token_tail}</code> 控制数量。</div>
    </div>
  </div>
</body>
</html>"#,
        rows = rows,
        token_q = token_q,
        token_tail = token_tail,
    );
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

#[get("/status")]
async fn status(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    let runtime = match state.runtime.read() {
        Ok(guard) => guard,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Config lock poisoned");
        }
    };
    if !check_auth(&req, &runtime.config, "status") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }
    let start = START_TIME.get().cloned().unwrap_or(std::time::SystemTime::now());
    let uptime = start
        .elapsed()
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let config_path = state
        .config_path
        .clone()
        .unwrap_or_else(|| "default".to_string());
    let protected = if runtime.config.auth.protect.is_empty() {
        String::from("none")
    } else {
        runtime.config.auth.protect.join(", ")
    };
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
    let alias_preview = runtime
        .config
        .alias
        .rules
        .iter()
        .take(6)
        .enumerate()
        .map(|(i, r)| {
            format!(
                "{}. {} => {}",
                i + 1,
                html_escape(&r.pattern),
                html_escape(&r.replace)
            )
        })
        .collect::<Vec<_>>()
        .join("<br/>");
    let group_preview = runtime
        .config
        .groups
        .entries
        .iter()
        .take(8)
        .map(|g| html_escape(&g.group))
        .collect::<Vec<_>>()
        .join(" · ");
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
  <style>
    :root {{
      --bg: #f6f7fb;
      --card: #ffffff;
      --text: #1a1f2b;
      --muted: #5b6b7f;
      --accent: #2b7fff;
      --ok: #1eaa6f;
      --border: #e3e7ef;
    }}
    body {{
      margin: 0;
      font-family: "Source Serif 4", "Noto Serif SC", "Source Serif Pro", serif;
      background:
        radial-gradient(800px 400px at 100% -10%, #dbe7ff, transparent),
        radial-gradient(900px 500px at -10% 10%, #ffe2c7, transparent),
        var(--bg);
      color: var(--text);
    }}
    .wrap {{
      max-width: 980px;
      margin: 40px auto;
      padding: 0 16px;
    }}
    .title {{
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 16px;
    }}
    .dot {{
      width: 12px;
      height: 12px;
      border-radius: 50%;
      background: var(--ok);
      box-shadow: 0 0 12px rgba(30, 170, 111, 0.4);
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
    }}
    .section {{
      margin-top: 24px;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
      box-shadow: 0 10px 30px rgba(16, 24, 40, 0.08);
    }}
    .label {{
      color: var(--muted);
      font-size: 12px;
      letter-spacing: 0.4px;
      text-transform: uppercase;
    }}
    .value {{
      margin-top: 6px;
      font-size: 20px;
      font-weight: 600;
    }}
    .pill {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      background: rgba(43, 127, 255, 0.1);
      color: var(--accent);
      font-size: 12px;
      margin-top: 8px;
    }}
    .small {{
      font-size: 14px;
      line-height: 1.6;
      color: var(--muted);
      margin-top: 6px;
    }}
    .small div {{
      margin-top: 6px;
    }}
    .link {{
      color: var(--accent);
      text-decoration: none;
      font-weight: 600;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="title">
      <div class="dot"></div>
      <h1>IPTV Proxy Status</h1>
    </div>
    <div class="section">
      <div class="grid">
        <div class="card">
          <div class="label">Status</div>
          <div class="value">OK</div>
          <div class="pill">Running</div>
        </div>
        <div class="card">
          <div class="label">Uptime</div>
          <div class="value">{uptime}s</div>
          <div class="small">since process start</div>
        </div>
        <div class="card">
          <div class="label">Config</div>
          <div class="value">{config_path}</div>
          <div class="small">manage: {manage_enabled}</div>
        </div>
        <div class="card">
          <div class="label">Protected</div>
          <div class="value">{protected}</div>
          <div class="small">auth token set: {token_set}</div>
        </div>
        <div class="card">
          <div class="label">Extra Playlists</div>
          <div class="value">{extra_playlist}</div>
        </div>
        <div class="card">
          <div class="label">Extra XMLTV</div>
          <div class="value">{extra_xmltv}</div>
        </div>
        <div class="card">
          <div class="label">Channels</div>
          <div class="value">{channels_count}</div>
          <div class="small"><a class="link" href="{channels_link}">查看全部</a></div>
        </div>
      </div>
    </div>
    <div class="section">
      <div class="card">
        <div class="label">Endpoints & Features</div>
        <div class="value">功能入口一览</div>
        <ul class="small" style="margin-top:10px;">
          <li><b>Playlist</b>: <a class="link" href="/playlist{token_q}">/playlist</a> - 输出 M3U 播放列表，支持别名/分组/排序</li>
          <li><b>XMLTV</b>: <a class="link" href="/xmltv{token_q}">/xmltv</a> - 输出 EPG（可选使用别名名称）</li>
          <li><b>Status</b>: <a class="link" href="/status{token_q}">/status</a> - 系统概览与规则摘要</li>
          <li><b>Manage</b>: <a class="link" href="/manage{token_q}">/manage</a> - 管理首页（导航）</li>
          <li><b>Manage Config</b>: <a class="link" href="/manage/config{token_q}">/manage/config</a> - 当前配置（TOML）</li>
          <li><b>Manage Reload</b>: <a class="link" href="/manage/reload{token_q}">/manage/reload</a> - 热加载配置</li>
          <li><b>Manage Test</b>: <a class="link" href="/manage/test?name=CCTV1{token_tail}">/manage/test?name=...</a> - 测试别名/分组/分辨率</li>
          <li><b>Channels (JSON)</b>: <a class="link" href="/manage/channels?limit=200{token_tail}">/manage/channels?limit=...</a> - 频道详情 JSON</li>
          <li><b>Channels (HTML)</b>: <a class="link" href="/manage/channels/html?limit=200{token_tail}">/manage/channels/html?limit=...</a> - 频道列表页面</li>
          <li><b>Logo</b>: <code>/logo/{{id}}.png</code> - 频道 Logo</li>
          <li><b>RTSP Proxy</b>: <code>/rtsp/{{tail}}</code> - RTSP 代理</li>
          <li><b>UDP Proxy</b>: <code>/udp/{{ip}}:{{port}}</code> - UDP 代理</li>
        </ul>
      </div>
    </div>
    <div class="section">
      <div class="grid">
        <div class="card">
          <div class="label">Alias Rules</div>
          <div class="value">{alias_rules}</div>
          <div class="small">{alias_preview}</div>
        </div>
        <div class="card">
          <div class="label">Groups</div>
          <div class="value">{group_count}</div>
          <div class="small">{group_preview}</div>
        </div>
      </div>
    </div>
  </div>
</body>
</html>"#,
        uptime = uptime,
        config_path = config_path,
        manage_enabled = if runtime.config.manage.enabled { "enabled" } else { "disabled" },
        protected = protected,
        token_set = if runtime.config.auth.token.is_empty() {
            "no"
        } else {
            "yes"
        },
        extra_playlist = state.args.extra_playlist.len(),
        extra_xmltv = state.args.extra_xmltv.len(),
        channels_count = channels_count,
        alias_rules = runtime.config.alias.rules.len(),
        group_count = runtime.config.groups.entries.len(),
        alias_preview = alias_preview,
        group_preview = group_preview,
        channels_link = channels_link,
        token_q = token_q,
        token_tail = token_tail,
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

fn usage(cmd: &str) -> std::io::Result<()> {
    let usage = format!(
        r#"Usage: {} [OPTIONS] --user <USER> --passwd <PASSWD> --mac <MAC>

Options:
    -u, --user <USER>                      Login username (or config [app].user)
    -p, --passwd <PASSWD>                  Login password (or config [app].passwd)
    -m, --mac <MAC>                        MAC address (or config [app].mac)
    -i, --imei <IMEI>                      IMEI (or config [app].imei) [default: ]
    -b, --bind <BIND>                      Bind address:port (or config [app].bind) [default: 0.0.0.0:7878]
    -a, --address <ADDRESS>                IP address/interface name (or config [app].address) [default: ]
    -I, --interface <INTERFACE>            Interface to request (or config [app].interface)
    -c, --config <CONFIG>                  Config file path (TOML)
        --extra-playlist <EXTRA_PLAYLIST>  Url to extra m3u
        --extra-xmltv <EXTRA_XMLTV>        Url to extra xmltv
        --udp-proxy                        Use UDP proxy
        --rtsp-proxy                       Use rtsp proxy
    -h, --help                             Print help
"#,
        cmd
    );
    eprint!("{}", usage);
    exit(0);
}

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let _ = START_TIME.set(std::time::SystemTime::now());
    let args = std::env::args().collect::<Vec<_>>();
    let args = args.iter().map(|s| s.as_str()).collect::<Vec<_>>();
    let args: &[&str] = args.as_ref();
    if args.is_empty() {
        return usage("iptv");
    }
    let args = match Args::from_args(&args[0..1], &args[1..]) {
        Ok(args) => args,
        Err(_) => {
            return usage(args[0]);
        }
    };

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
