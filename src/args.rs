use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub(crate) struct Args {
    #[arg(short, long, help = "Login username")]
    pub(crate) user: String,

    #[arg(short, long, help = "Login password")]
    pub(crate) passwd: String,

    #[arg(short, long, help = "MAC address")]
    pub(crate) mac: String,

    #[arg(short, long, help = "IMEI", default_value_t = String::from(""))]
    pub(crate) imei: String,

    #[arg(short, long, help = "Bind address:port", default_value_t = String::from("127.0.0.1:7878"))]
    pub(crate) bind: String,

    #[arg(short, long, help = "IP address/interface name", default_value_t = String::from(""))]
    pub(crate) address: String,

    #[arg(short = 'I', long, help = "Interface to request")]
    pub(crate) interface: Option<String>,

    #[arg(long, help = "Url to extra m3u")]
    pub(crate) extra_playlist: Option<String>,

    #[arg(long, help = "Url to extra xmltv")]
    pub(crate) extra_xmltv: Option<String>,

    #[arg(long, help = "UDP proxy address:port")]
    pub(crate) udp_proxy: Option<String>,

    #[arg(long, help = "Use rtsp proxy", default_value_t = false)]
    pub(crate) rtsp_proxy: bool,
}
