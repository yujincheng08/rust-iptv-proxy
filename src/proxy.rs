use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};

use actix_web::web::Bytes;
use anyhow::{anyhow, Result};
use async_stream::stream;
use futures_core::stream::Stream;
use futures_util::stream::StreamExt;
use local_ip_address::list_afinet_netifas;
use log::{debug, error, info};
use reqwest::Url;
use retina::client::{PacketItem, Session, SessionOptions};
use rtp_rs::RtpReader;
use tokio::{net::UdpSocket, sync::broadcast};

// IPTV RTP packets generally contain seven 188-byte MPEG-TS packets. Sending
// every RTP payload as a separate HTTP body chunk creates far more allocator,
// scheduler, and HTTP framing work than the payload itself warrants. msd_lite
// also uses a 64 KiB minimum send block by default.
const HTTP_CHUNK_TARGET: usize = 64 * 1024;
const MAX_UDP_PACKET_SIZE: usize = u16::MAX as usize;
const UDP_HUB_CAPACITY: usize = 16;
const UDP_HUB_CACHE_SIZE: usize = 1024 * 1024;
const UDP_HUB_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct UdpHubKey {
    multi_addr: SocketAddrV4,
    if_name: Option<String>,
}

struct UdpHubState {
    tx: broadcast::Sender<Bytes>,
    cache: VecDeque<Bytes>,
    cache_size: usize,
}

struct UdpHub {
    state: Mutex<UdpHubState>,
}

impl UdpHub {
    fn new() -> Self {
        let (tx, _) = broadcast::channel(UDP_HUB_CAPACITY);
        Self {
            state: Mutex::new(UdpHubState {
                tx,
                cache: VecDeque::with_capacity(UDP_HUB_CAPACITY),
                cache_size: 0,
            }),
        }
    }

    fn subscribe(&self) -> Result<(Vec<Bytes>, broadcast::Receiver<Bytes>)> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow!("UDP hub state lock poisoned"))?;
        // Snapshot and subscribe under the same lock so no chunk can be lost
        // or duplicated at the cache/live boundary.
        let cached = state.cache.iter().cloned().collect();
        let rx = state.tx.subscribe();
        Ok((cached, rx))
    }

    fn publish(&self, bytes: Bytes) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("UDP hub state lock poisoned"))?;
        state.cache_size += bytes.len();
        state.cache.push_back(bytes.clone());
        while state.cache_size > UDP_HUB_CACHE_SIZE {
            if let Some(expired) = state.cache.pop_front() {
                state.cache_size -= expired.len();
            }
        }
        state.tx.send(bytes).ok();
        Ok(())
    }

    fn receiver_count(&self) -> Result<usize> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow!("UDP hub state lock poisoned"))?;
        Ok(state.tx.receiver_count())
    }
}

static UDP_HUBS: LazyLock<Mutex<HashMap<UdpHubKey, Arc<UdpHub>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn filter_reordered_seq(seq: &mut Option<u16>, next: u16) -> bool {
    match *seq {
        None => {
            *seq = Some(next);
            true
        }
        Some(previous) if (1..=3000).contains(&next.wrapping_sub(previous)) => {
            *seq = Some(next);
            true
        }
        Some(_) => false,
    }
}

fn looks_like_mpeg_ts(data: &[u8]) -> bool {
    data.len() >= 188 && data[0] == 0x47 && (data.len() < 376 || data.get(188) == Some(&0x47))
}

pub(crate) fn rtsp(url: String, if_name: Option<String>) -> impl Stream<Item = Result<Bytes>> {
    stream! {
        let log_url = url.split_once('?').map_or(url.as_str(), |(base, _)| base);
        info!("RTSP proxy {log_url}");
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

        let mut seq = None;
        while let Some(item) = playing.next().await {
            match item {
                Ok(PacketItem::Rtp(packet)) => {
                    if filter_reordered_seq(&mut seq, packet.sequence_number()) {
                        yield Ok(packet.into_payload_bytes());
                    }
                }
                Ok(PacketItem::Rtcp(_)) => {}
                Ok(_) => {}
                Err(e) => {
                    error!("RTSP stream closed: {e}");
                    break;
                }
            }
        }
    }
}

async fn run_udp_hub(key: UdpHubKey, hub: Arc<UdpHub>) -> Result<()> {
    let multi_addr = key.multi_addr;
    let if_name = key.if_name.as_deref();

    let result = async {
        let socket = {
            let socket = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;
            socket.set_reuse_address(true)?;
            socket.set_recv_buffer_size(1024 * 1024)?;
            socket.set_nonblocking(true)?;
            #[cfg(not(target_os = "windows"))]
            {
                socket.bind(&multi_addr.into())?;
            }
            #[cfg(target_os = "windows")]
            {
                socket.bind(
                    &SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), multi_addr.port()).into(),
                )?;
            }
            UdpSocket::from_std(socket.into())?
        };

        let mut interface = Ipv4Addr::new(0, 0, 0, 0);
        if let Some(i) = if_name {
            let network_interfaces = list_afinet_netifas()?;
            for (name, ip) in network_interfaces.iter() {
                debug!("{}: {}", name, ip);
                if name != i {
                    continue;
                }
                if let IpAddr::V4(ip) = ip {
                    interface = *ip;
                    break;
                }
            }
        }

        socket.join_multicast_v4(*multi_addr.ip(), interface)?;

        info!("Udp proxy joined {}", multi_addr);

        let mut packet = vec![0u8; MAX_UDP_PACKET_SIZE];
        let mut output = Vec::with_capacity(HTTP_CHUNK_TARGET + 2048);
        let mut seq = None;
        let mut idle_since = None;

        loop {
            let received =
                tokio::time::timeout(UDP_HUB_IDLE_TIMEOUT, socket.recv_from(&mut packet)).await;

            if hub.receiver_count()? == 0 {
                let idle_since = idle_since.get_or_insert_with(Instant::now);
                if idle_since.elapsed() >= UDP_HUB_IDLE_TIMEOUT {
                    let mut hubs = UDP_HUBS
                        .lock()
                        .map_err(|_| anyhow!("UDP hub registry lock poisoned"))?;
                    let is_current = hubs
                        .get(&key)
                        .is_some_and(|current| Arc::ptr_eq(current, &hub));
                    if is_current && hub.receiver_count()? == 0 {
                        hubs.remove(&key);
                        break;
                    }
                }
            } else {
                idle_since = None;
            }

            let len = match received {
                Ok(Ok((len, _))) => len,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => continue,
            };
            let data = &packet[..len];
            if looks_like_mpeg_ts(data) {
                output.extend_from_slice(data);
            } else {
                let rtp = match RtpReader::new(data) {
                    Ok(rtp) => rtp,
                    Err(e) => {
                        debug!("Dropping invalid RTP packet from {multi_addr}: {e:?}");
                        continue;
                    }
                };
                let next = rtp.sequence_number().into();
                if !filter_reordered_seq(&mut seq, next) {
                    continue;
                }
                output.extend_from_slice(rtp.payload());
            }
            if output.len() >= HTTP_CHUNK_TARGET {
                let chunk =
                    std::mem::replace(&mut output, Vec::with_capacity(HTTP_CHUNK_TARGET + 2048));
                hub.publish(Bytes::from(chunk))?;
            }
        }

        socket.leave_multicast_v4(*multi_addr.ip(), interface).ok();
        info!("Udp proxy left {}", multi_addr);
        Ok(())
    }
    .await;

    let mut hubs = UDP_HUBS
        .lock()
        .map_err(|_| anyhow!("UDP hub registry lock poisoned"))?;
    if hubs
        .get(&key)
        .is_some_and(|current| Arc::ptr_eq(current, &hub))
    {
        hubs.remove(&key);
    }
    result
}

fn subscribe_udp_hub(key: &UdpHubKey) -> Result<(Vec<Bytes>, broadcast::Receiver<Bytes>)> {
    let mut hubs = UDP_HUBS
        .lock()
        .map_err(|_| anyhow!("UDP hub registry lock poisoned"))?;
    if let Some(hub) = hubs.get(key) {
        return hub.subscribe();
    }

    let hub = Arc::new(UdpHub::new());
    let subscription = hub.subscribe()?;
    hubs.insert(key.clone(), hub.clone());
    let task_key = key.clone();
    tokio::spawn(async move {
        if let Err(e) = run_udp_hub(task_key, hub).await {
            error!("UDP proxy failed: {e}");
        }
    });
    Ok(subscription)
}

pub(crate) fn udp(
    multi_addr: SocketAddrV4,
    if_name: Option<String>,
) -> impl Stream<Item = Result<Bytes>> {
    stream! {
        let key = UdpHubKey { multi_addr, if_name };
        let (cached, mut rx) = subscribe_udp_hub(&key)?;

        for bytes in cached {
            yield Ok(bytes);
        }

        loop {
            match rx.recv().await {
                Ok(bytes) => yield Ok(bytes),
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    debug!("Slow UDP proxy client skipped {skipped} chunk(s) for {multi_addr}");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{filter_reordered_seq, looks_like_mpeg_ts};

    #[test]
    fn sequence_filter_accepts_forward_progress_and_wraparound() {
        let mut seq = None;
        assert!(filter_reordered_seq(&mut seq, 65_530));
        assert!(filter_reordered_seq(&mut seq, 2));
        assert!(filter_reordered_seq(&mut seq, 1_000));
    }

    #[test]
    fn sequence_filter_rejects_duplicates_reordering_and_large_jumps() {
        let mut seq = None;
        assert!(filter_reordered_seq(&mut seq, 1_000));
        assert!(!filter_reordered_seq(&mut seq, 1_000));
        assert!(!filter_reordered_seq(&mut seq, 999));
        assert!(!filter_reordered_seq(&mut seq, 4_001));
    }

    #[test]
    fn zero_is_a_regular_sequence_number() {
        let mut seq = None;
        assert!(filter_reordered_seq(&mut seq, 0));
        assert!(!filter_reordered_seq(&mut seq, 4_000));
        assert!(filter_reordered_seq(&mut seq, 1));
    }

    #[test]
    fn detects_raw_mpeg_ts_datagrams() {
        let mut packet = vec![0; 188 * 7];
        for offset in (0..packet.len()).step_by(188) {
            packet[offset] = 0x47;
        }
        assert!(looks_like_mpeg_ts(&packet));
        packet[188] = 0;
        assert!(!looks_like_mpeg_ts(&packet));
    }
}
