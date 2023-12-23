use clap::Parser;
use des::{
    cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyInit},
    TdesEde3,
};
#[macro_use]
extern crate lazy_static;
use log::{debug, error, info, warn};
use rand::Rng;
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use std::{
    collections::HashMap,
    error::Error,
    io::prelude::*,
    net::{TcpListener, TcpStream},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime},
};
use tokio::sync::{RwLock, RwLockReadGuard};

type ChannelMap = HashMap<u64, HashMap<String, String>>;

type ChannelCache = RwLock<ChannelMap>;

lazy_static! {
    static ref CHANNEL_CACHE: ChannelCache = ChannelCache::new(ChannelMap::new());
}

static LAST_UPDATE_TIME: AtomicU64 = AtomicU64::new(0);

#[derive(Deserialize)]
struct AuthJson {
    epgurl: String,
}

#[derive(Deserialize)]
struct TokenJson {
    #[serde(rename = "EncryToken")]
    encry_token: String,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, help = "Login username")]
    user: String,

    #[clap(short, long, help = "Login password")]
    passwd: String,

    #[clap(short, long, help = "MAC address", validator_regex(Regex::new("([0-9A-F]{2}[:]){5}([0-9A-F]{2})").unwrap(), "Should be in upper case and seperated by colon"))]
    mac: String,

    #[clap(short, long, help = "IMEI", default_value_t = String::from(""))]
    imei: String,

    #[clap(short, long, help = "bind address", default_value_t = String::from("127.0.0.1:7878"))]
    bind: String,

    #[clap(short, long, help = "ip address/interface name", default_value_t = String::from(""))]
    address: String,
}

lazy_static! {
    static ref ARGS: Args = Args::parse();
}

async fn get_channels() -> Result<RwLockReadGuard<'static, ChannelMap>, Box<dyn Error>> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let last_update_time = LAST_UPDATE_TIME.load(Ordering::Acquire);

    let mut channel_gurad = if now - last_update_time > 60 * 60 * 24 {
        let gurad = CHANNEL_CACHE.write().await;
        if LAST_UPDATE_TIME
            .compare_exchange(last_update_time, now, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(gurad.downgrade());
        }
        gurad
    } else {
        return Ok(CHANNEL_CACHE.read().await);
    };

    info!("Updating channels");

    let user = ARGS.user.as_str();
    let passwd = ARGS.passwd.as_str();
    let mac = ARGS.mac.as_str();
    let imei = ARGS.imei.as_str();
    let ip = ARGS.address.as_str();

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

    let response = client.get(url).send().await?;

    let base_url = if response.status().is_success() {
        let auth: AuthJson = response.json().await?;
        let epgurl = reqwest::Url::parse(auth.epgurl.as_str())?;
        format!(
            "{}://{}:{}",
            epgurl.scheme(),
            epgurl.host_str().ok_or("no host")?,
            epgurl.port_or_known_default().ok_or("no port")?,
        )
    } else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "Failed to get base url",
        )));
    };

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
    let response = client.get(url).send().await?;

    let token = if response.status().is_success() {
        let auth: TokenJson = response.json().await?;
        auth.encry_token
    } else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Failed to parse token",
        )));
    };

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
    let response = client.get(url).send().await?;

    if !response.status().is_success() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            format!("failed {}", response.status()),
        )));
    }

    let url = reqwest::Url::parse(format!("{base_url}/EPG/jsp/getchannellistHWCTC.jsp").as_str())?;

    let response = client.get(url).send().await?;

    if response.status().is_success() {
        let res = response.text().await?;
        let re = Regex::new("Authentication.CTCSetConfig\\('Channel','(.+?)'\\)")?;
        let mut channels = re
            .captures_iter(&res)
            .map(|cap| cap[1].to_string())
            .map(|s| {
                s.split("\",")
                    .map(|s| s.split("=\"").collect::<Vec<_>>())
                    .filter(|s| s.len() == 2)
                    .map(|p| {
                        (
                            String::from(*p.iter().nth(0).unwrap()),
                            String::from(*p.iter().nth(1).unwrap()),
                        )
                    })
                    .collect::<HashMap<_, _>>()
            })
            .collect::<Vec<_>>();
        let channels = channels
            .iter_mut()
            .filter(|c| c.contains_key("ChannelID") && c.contains_key("ChannelURL"))
            .filter_map(|c| match c["ChannelURL"].split("|").find(|u| u.starts_with("rtsp")) {
                    None => None,
                    Some(i) => {
                        c.insert("ChannelURL".to_owned(), i.to_owned());
                        Some(c)
                    },
                }
            )
            .filter_map(|c| {
                debug!("{}={}", c["ChannelID"], c["ChannelURL"]);
                match str::parse::<u64>(&c["ChannelID"]) {
                Ok(i) => Some((i, c.to_owned())),
                Err(_) => None,
            }})
            .collect::<HashMap<_, _>>();

        info!("Got {} channel(s)", channels.len());
        for (id, channel) in channels.iter() {
            info!(
                "Channel {} in id {}",
                channel
                    .get("ChannelName")
                    .unwrap_or(&String::from("UNKNOWN")),
                id
            );
        }
        *channel_gurad = channels;
        Ok(channel_gurad.downgrade())
    } else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "Failed to fetch channel",
        )));
    }
}

async fn handle_connection(mut stream: TcpStream) -> Result<(), Box<dyn Error>> {
    // Read the first 1024 bytes of data from the stream
    let channels = get_channels().await?;
    let mut buffer = [0; 1024];
    debug!("Begin handle connection {}", stream.peer_addr()?);
    let n = stream.read(&mut buffer)?;
    let req = &buffer[0..n];
    if !req.ends_with(b"\r\n\r\n") {
        rtsp_types::Response::builder(
            rtsp_types::Version::V1_0,
            rtsp_types::StatusCode::RequestMessageBodyTooLarge,
        )
        .header(rtsp_types::headers::CSEQ, "1")
        .empty()
        .write(&mut stream)?;
        stream.flush()?;
    }

    debug!("Got first header");

    let (message, _): (rtsp_types::Message<Vec<u8>>, _) = rtsp_types::Message::parse(&buffer)?;

    let cseq = match message {
        rtsp_types::Message::Request(ref request) => {
            if request.method() != rtsp_types::Method::Options {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Not support method for the first request",
                )));
            }
            request
                .header(&rtsp_types::headers::CSEQ)
                .ok_or("No CSEQ")?
        }
        _ => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Only request is supported",
            )))
        }
    };

    debug!("Respone first request");

    rtsp_types::Response::builder(rtsp_types::Version::V1_0, rtsp_types::StatusCode::Ok)
        .header(rtsp_types::headers::CSEQ, "2")
        .empty()
        .write(&mut stream)?;
    stream.flush()?;

    let n = stream.read(&mut buffer)?;
    let req = &buffer[0..n];
    if !req.ends_with(b"\r\n\r\n") {
        rtsp_types::Response::builder(
            rtsp_types::Version::V1_0,
            rtsp_types::StatusCode::RequestMessageBodyTooLarge,
        )
        .header(rtsp_types::headers::CSEQ, cseq.clone())
        .empty()
        .write(&mut stream)?;
        stream.flush()?;
    }

    debug!("Got second header");

    let (message, _): (rtsp_types::Message<Vec<u8>>, _) = rtsp_types::Message::parse(&buffer)?;

    let (url, cseq) = match message {
        rtsp_types::Message::Request(ref request) => {
            if request.method() != rtsp_types::Method::Describe {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Not support method for the second request",
                )));
            }
            (
                request.request_uri().ok_or("Request url is empty")?,
                request
                    .header(&rtsp_types::headers::CSEQ)
                    .ok_or("No CSEQ")?,
            )
        }
        _ => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Only request is supported",
            )))
        }
    };

    let id = str::parse::<u64>(&url.path().clone()[1..])?;

    let channel_url = match channels.get(&id) {
        Some(channel_url) => channel_url.get("ChannelURL").unwrap(),
        None => {
            warn!("channel {id} not found");
            rtsp_types::Response::builder(
                rtsp_types::Version::V1_0,
                rtsp_types::StatusCode::NotFound,
            )
            .header(rtsp_types::headers::CSEQ, cseq.clone())
            .empty()
            .write(&mut stream)?;
            return Ok(());
        }
    };

    debug!("Respone second request");

    rtsp_types::Response::builder(rtsp_types::Version::V1_0, rtsp_types::StatusCode::Found)
        .header(rtsp_types::headers::CSEQ, cseq.clone())
        .header(rtsp_types::headers::LOCATION, channel_url.clone())
        .empty()
        .write(&mut stream)?;
    stream.flush()?;

    Ok(())
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let arg = &*ARGS;
    let listener = TcpListener::bind(&arg.bind).unwrap();
    info!("Binding on {}", arg.bind);

    // Block forever, handling each request that arrives at this IP address
    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream).await {
                    error!("Error {e}");
                }    
            });
        }
    }
}
