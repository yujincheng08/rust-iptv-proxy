use actix_web::{get, web::Data, App, HttpServer, Responder};
use anyhow::{anyhow, Result};
use chrono::{FixedOffset, TimeZone, Utc};
use clap::Parser;
use des::{
    cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyInit},
    TdesEde3,
};
use log::{debug, info};
use rand::Rng;
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use std::{
    collections::HashMap,
    io::BufWriter,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::task::JoinSet;
use xml::writer::{EmitterConfig, XmlEvent};

struct Program {
    start: i64,
    stop: i64,
    title: String,
    desc: String,
}

struct Channel {
    id: u64,
    name: String,
    url: String,
    epg: Vec<Program>,
}

#[derive(Deserialize)]
struct AuthJson {
    epgurl: String,
}

#[derive(Deserialize)]
struct TokenJson {
    #[serde(rename = "EncryToken")]
    encry_token: String,
}

#[derive(Deserialize)]
struct PlaybillList {
    #[serde(rename = "playbillLites")]
    list: Vec<Bill>,
}

#[derive(Deserialize)]
struct Bill {
    name: String,
    #[serde(rename = "startTime")]
    start_time: i64,
    #[serde(rename = "endTime")]
    end_time: i64,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, help = "Login username")]
    user: String,

    #[arg(short, long, help = "Login password")]
    passwd: String,

    #[arg(short, long, help = "MAC address")]
    mac: String,

    #[arg(short, long, help = "IMEI", default_value_t = String::from(""))]
    imei: String,

    #[arg(short, long, help = "bind address", default_value_t = String::from("127.0.0.1:7878"))]
    bind: String,

    #[arg(short, long, help = "ip address/interface name", default_value_t = String::from(""))]
    address: String,
}

async fn get_channels(args: &Args, need_epg: bool) -> Result<Vec<Channel>> {
    info!("Obtaining channels");

    let user = args.user.as_str();
    let passwd = args.passwd.as_str();
    let mac = args.mac.as_str();
    let imei = args.imei.as_str();
    let ip = args.address.as_str();

    let timeout = Duration::new(5, 0);
    let client = Client::builder()
        // .local_address(addr)
        .timeout(timeout)
        .cookie_store(true)
        .build()?;

    let params = [("Action", "Login"), ("return_type", "1"), ("UserID", user)];

    let url = reqwest::Url::parse_with_params(
        "http://eds.iptv.gd.cn:8082/EDS/jsp/AuthenticationURL",
        params,
    )?;

    let response = client.get(url).send().await?.error_for_status()?;

    let epgurl = reqwest::Url::parse(response.json::<AuthJson>().await?.epgurl.as_str())?;
    let base_url = format!(
        "{}://{}:{}",
        epgurl.scheme(),
        epgurl.host_str().ok_or(anyhow!("no host"))?,
        epgurl.port_or_known_default().ok_or(anyhow!("no host"))?,
    );
    debug!("Got base_url {base_url}");

    let params = [
        ("response_type", "EncryToken"),
        ("client_id", "smcphone"),
        ("userid", user),
    ];
    let url = reqwest::Url::parse_with_params(
        format!("{base_url}/EPG/oauth/v2/authorize").as_str(),
        params,
    )?;
    let response = client.get(url).send().await?.error_for_status()?;

    let token = response.json::<TokenJson>().await?.encry_token;

    debug!("Got token {token}");

    let enc = ecb::Encryptor::<TdesEde3>::new_from_slice(
        format!("{:X}", md5::compute(passwd.as_bytes()))[0..24].as_bytes(),
    );
    let enc = match enc {
        Ok(enc) => Ok(enc),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("Encrpy error {e}"),
        )),
    }?;
    let data = format!(
        "{}${token}${user}${imei}${ip}${mac}$$CTC",
        rand::thread_rng().gen_range(0..10000000),
    );
    let auth = hex::encode_upper(enc.encrypt_padded_vec_mut::<Pkcs7>(data.as_bytes()));

    debug!("Got auth {auth}");

    let params = [
        ("client_id", "smcphone"),
        ("DeviceType", "deviceType"),
        ("UserID", user),
        ("DeviceVersion", "deviceVersion"),
        ("userdomain", "2"),
        ("datadomain", "3"),
        ("accountType", "1"),
        ("authinfo", auth.as_str()),
        ("grant_type", "EncryToken"),
    ];
    let url =
        reqwest::Url::parse_with_params(format!("{base_url}/EPG/oauth/v2/token").as_str(), params)?;
    let _response = client.get(url).send().await?.error_for_status()?;

    let url = reqwest::Url::parse(format!("{base_url}/EPG/jsp/getchannellistHWCTC.jsp").as_str())?;

    let response = client.get(url).send().await?.error_for_status()?;

    let res = response.text().await?;
    let re = Regex::new("Authentication.CTCSetConfig\\('Channel','(.+?)'\\)")?;
    let mut channels = re
        .captures_iter(&res)
        .map(|cap| cap[1].to_string())
        .map(|s| {
            s.split("\",")
                .map(|s| s.split("=\"").collect::<Vec<_>>())
                .filter_map(|s| {
                    s.get(0)
                        .map(|a| String::from(*a))
                        .and_then(|a| s.get(1).map(|b| String::from(*b)).map(|b| (a, b)))
                })
                .collect::<HashMap<_, _>>()
        })
        .collect::<Vec<_>>();

    let channels = channels
        .iter_mut()
        .filter_map(|m| {
            m.get("ChannelID")
                .and_then(|i| str::parse::<u64>(i).ok())
                .map(|i| (i, m))
        })
        .filter_map(|(i, m)| {
            m.get("ChannelName")
                .map(|n| n.clone())
                .map(|n| (i, n, m))
        })
        .filter_map(|(i, n, m)| {
            m.get("ChannelURL")
                .and_then(|u| u.split("|").find(|u| u.starts_with("rtsp")))
                .map(|u| u.replace("zoneoffset=0", "zoneoffset=480"))
                .map(|u| (i, n, u))
        })
        .map(|(i, n, u)| Channel {
            id: i,
            name: n.to_owned(),
            url: u.to_owned(),
            epg: vec![],
        })
        .collect::<Vec<_>>();

    info!("Got {} channel(s)", channels.len());

    if !need_epg {
        return Ok(channels);
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();

    let mut tasks = JoinSet::new();

    for channel in channels.into_iter() {
        let params = [
            ("channelId", format!("{}", channel.id)),
            ("begin", format!("{}", now - 86400000 * 2)),
            ("end", format!("{}", now + 86400000 * 5)),
        ];
        let url = reqwest::Url::parse_with_params(
            format!("{base_url}/EPG/jsp/iptvsnmv3/en/play/ajax/_ajax_getPlaybillList.jsp").as_str(),
            params,
        )?;
        let client = client.clone();
        tasks.spawn(async move { (client.get(url).send().await, channel) });
    }
    let mut channels = vec![];
    while let Some(Ok((Ok(res), mut channel))) = tasks.join_next().await {
        if let Ok(play_bill_list) = res.json::<PlaybillList>().await {
            for bill in play_bill_list.list.into_iter() {
                channel.epg.push(Program {
                    start: bill.start_time,
                    stop: bill.end_time,
                    title: bill.name.clone(),
                    desc: bill.name,
                })
            }
        }
        channels.push(channel);
    }

    Ok(channels)
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

fn to_xmltv(channels: Vec<Channel>) -> Result<String> {
    let mut buf = BufWriter::new(Vec::new());
    let mut writer = EmitterConfig::new()
        .perform_indent(false)
        .create_writer(&mut buf);
    writer.write(
        XmlEvent::start_element("tv")
            .attr("generator-info-name", "iptv-proxy")
            .attr("source-info-name", "iptv-proxy"),
    )?;
    for channel in channels.iter() {
        writer.write(XmlEvent::start_element("channel").attr("id", &format!("{}", channel.id)))?;
        writer.write(XmlEvent::start_element("display-name"))?;
        writer.write(XmlEvent::characters(&channel.name))?;
        writer.write(XmlEvent::end_element())?;
        writer.write(XmlEvent::end_element())?;
    }
    for channel in channels.iter() {
        for epg in channel.epg.iter() {
            writer.write(
                XmlEvent::start_element("programme")
                    .attr("start", &format!("{} +0800", to_xmltv_time(epg.start)?))
                    .attr("stop", &format!("{} +0800", to_xmltv_time(epg.stop)?))
                    .attr("channel", &format!("{}", channel.id)),
            )?;
            writer.write(XmlEvent::start_element("title").attr("lang", "chi"))?;
            writer.write(XmlEvent::characters(&epg.title))?;
            writer.write(XmlEvent::end_element())?;
            if !epg.desc.is_empty() {
                writer.write(XmlEvent::start_element("desc"))?;
                writer.write(XmlEvent::characters(&epg.desc))?;
                writer.write(XmlEvent::end_element())?;
            }
            writer.write(XmlEvent::end_element())?;
        }
    }
    writer.write(XmlEvent::end_element())?;
    Ok(String::from_utf8(buf.into_inner()?)?)
}

#[get("/xmltv")]
async fn xmltv(args: Data<Args>) -> impl Responder {
    debug!("Get EPG");
    match get_channels(&*args, true).await.and_then(|ch| to_xmltv(ch)) {
        Err(e) => format!("{}", e),
        Ok(xml) => xml,
    }
}

#[get("playlist")]
async fn playlist(args: Data<Args>) -> impl Responder {
    debug!("Get playlist");
    match get_channels(&*args, false).await {
        Err(e) => format!("{}", e),
        Ok(ch) => {
            String::from("#EXTM3U\n")
                + &ch
                    .into_iter()
                    .map(|c| {
                        format!(
                            r#"#EXTINF:-1 tvg-id="{0}" tvg-name="{1}" tvg-chno="{0}",{1}"#,
                            c.id, c.name
                        ) + "\n"
                            + &c.url
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
        }
    }
}

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    HttpServer::new(|| {
        let args = Data::new(Args::parse());
        App::new().service(xmltv).service(playlist).app_data(args)
    })
    .bind(Args::parse().bind)?
    .run()
    .await
}
