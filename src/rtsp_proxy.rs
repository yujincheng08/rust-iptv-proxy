use actix_web::web::Bytes;
use anyhow::Result;
use async_stream::stream;
use futures_core::stream::Stream;
use futures_util::stream::StreamExt;
#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
use local_ip_address::list_afinet_netifas;
use log::{debug, error};
use reqwest::Url;
use retina::client::{PacketItem, Session, SessionOptions};
use tokio::sync::mpsc;

pub(crate) fn rtsp_proxy(
    url: String,
    if_name: Option<String>,
) -> impl Stream<Item = Result<Bytes>> {
    stream! {
        let mut options = SessionOptions::default().follow_redirects(true);
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        if let Some(i) = if_name {
            let network_interfaces = list_afinet_netifas()?;
            for (name, ip) in network_interfaces.iter() {
                debug!("{}: {}", name, ip);
                if name == i {
                    options = options.bind(ip);
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

        debug!("RTSP session created with {} streams", session.streams().len());

        for i in 0..session.streams().len() {
            session.setup(i, Default::default()).await?;
        }
        let mut playing = session.play(Default::default()).await?;

        let (tx, mut rx) = mpsc::channel(128);

        tokio::spawn(async move {
            while let Some(item) = playing.next().await {
                if let Ok(PacketItem::Rtp(stream)) = item {
                    if tx.send(stream).await.is_ok() {
                        continue;
                    }
                }
                break;
            }
        });

        loop {
            let stream = rx.recv().await;
            if let Some(stream) = stream {
                yield Ok(stream.into_payload_bytes());
            } else {
                error!("Connection closed");
                break;
            }
        }

        // let mut seq = 0;
        // while let Some(stream) = playing.next().await {
        //     if let PacketItem::Rtp(stream) = stream? {
        //         // if seq > stream.sequence_number() {
        //         //     continue;
        //         // }
        //         // seq = stream.sequence_number();
        //         yield Ok(stream.into_payload_bytes());
        //     } else {
        //         yield Err(anyhow::anyhow!("Unexpected packet type"));
        //     }
        // }
        // yield Ok(stream.into_payload_bytes());
    }
}
