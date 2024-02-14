use actix_web::web::Bytes;
use anyhow::Result;
use async_stream::stream;
use futures_core::stream::Stream;
use futures_util::stream::StreamExt;
use lazy_static::lazy_static;
#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
use local_ip_address::list_afinet_netifas;
use log::{error, info};
use reqwest::Url;
use retina::client::{PacketItem, Session, SessionOptions};
use rtp_rs::RtpReader;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Mutex;
use tokio::{
    net::UdpSocket,
    sync::{
        broadcast::{
            self,
            error::RecvError,
            Sender,
        },
        mpsc::{self},
    },
};
use tokio_util::{
    bytes::{Buf, BytesMut},
    codec::BytesCodec,
    udp::UdpFramed,
};

fn filter_reordered_seq(seq: &mut u16, next: u16) -> bool {
    let valid = seq.wrapping_add(3000);
    if *seq == 0
        || (valid > *seq && next > *seq && next <= valid)
        || (valid < *seq && (next > *seq || next <= valid))
    {
        *seq = next;
        true
    } else {
        false
    }
}

pub(crate) fn rtsp(url: String, if_name: Option<String>) -> impl Stream<Item = Result<Bytes>> {
    stream! {
        let mut options = SessionOptions::default().follow_redirects(true);
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        if let Some(ref i) = if_name {
            use log::debug;
            let network_interfaces = list_afinet_netifas()?;
            for (name, ip) in network_interfaces.iter() {
                debug!("{}: {}", name, ip);
                if name == i {
                    options = options.bind(ip.to_string());
                    break;
                }
            }
        }

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(i) = if_name {
            options = options.bind(i);
        }
        let mut session = match Session::describe(Url::parse(&url)?, options).await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to create RTSP session: {}", e);
                return;
            }
        };

        info!("RTSP session created with {} streams", session.streams().len());

        for i in 0..session.streams().len() {
            session.setup(i, Default::default()).await?;
        }
        let mut playing = session.play(Default::default()).await?;

        let (tx, mut rx) = mpsc::channel(128);

        tokio::spawn(async move {
            let mut seq = 0u16;
            while let Some(item) = playing.next().await {
                if let Ok(PacketItem::Rtp(stream)) = item {
                    if !filter_reordered_seq(&mut seq, stream.sequence_number()) ||
                        tx.send(stream.into_payload_bytes()).await.is_ok() {
                        continue;
                    }
                }
                break;
            }
        });

        loop {
            if let Some(stream) = rx.recv().await {
                yield Ok(stream);
            } else {
                error!("Connection closed");
                break;
            }
        }
    }
}

lazy_static! {
    static ref UDP_CHANNELS: Mutex<HashMap<SocketAddrV4, Sender<BytesMut>>> =
        Mutex::new(HashMap::new());
}

async fn join_multicast(multi_addr: SocketAddrV4, tx: Sender<BytesMut>) -> Result<()> {
    #[cfg(target_os = "windows")]
    let socket = {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_reuse_address(true)?;
        socket.bind(&SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), multi_addr.port()).into())?;
        UdpSocket::from_std(socket.into())?
    };
    #[cfg(not(target_os = "windows"))]
    let socket = { UdpSocket::bind(multi_addr).await? };
    socket.set_multicast_loop_v4(true)?;

    socket.join_multicast_v4(multi_addr.ip().clone(), Ipv4Addr::new(0, 0, 0, 0))?;

    info!("Udp proxy joined {}", multi_addr);

    let mut stream = UdpFramed::new(socket, BytesCodec::new());

    let mut seq = 0u16;
    while let Some(item) = stream.next().await {
        if let Ok((mut bytes, _)) = item {
            if let Ok(rtp) = RtpReader::new(bytes.as_ref()) {
                let next = rtp.sequence_number().into();
                bytes.advance(rtp.payload_offset());
                if filter_reordered_seq(&mut seq, next) &&
                    tx.send(bytes).map(|cnt| cnt > 0).unwrap_or(false) {
                    continue;
                }
            }
        }
        info!("Udp proxy left {}", multi_addr);
        stream
            .get_mut()
            .leave_multicast_v4(multi_addr.ip().clone(), Ipv4Addr::new(0, 0, 0, 0))
            .ok();
        UDP_CHANNELS.lock().unwrap().remove(&multi_addr);
        break;
    }

    Ok(())
}

pub(crate) fn udp(multi_addr: SocketAddrV4) -> impl Stream<Item = Result<Bytes>> {
    let (tx, mut rx) = {
        let mut channels = UDP_CHANNELS.lock().unwrap();
        match channels.get_mut(&multi_addr) {
            Some(tx) => (None, tx.subscribe()),
            None => {
                let (tx, rx) = broadcast::channel(128);
                channels.insert(multi_addr, tx.clone());
                (Some(tx), rx)
            }
        }
    };
    stream! {
        if let Some(tx) = tx {
            tokio::spawn(join_multicast(multi_addr, tx));
        }
        loop {
            match rx.recv().await {
                Ok(stream) =>  {
                    yield Ok(Bytes::from(stream));
                },
                Err(RecvError::Lagged(_)) => {
                    rx = rx.resubscribe()
                },
                Err(RecvError::Closed) => {
                    error!("Connection closed");
                    break;
                }
            }
        }
        yield Ok(Bytes::from("hello"))
    }
}
