use clap::Parser;

#[derive(Parser, Clone)]
#[command(name = "iptv")]
pub(crate) struct Args {
    #[arg(short = 'u', long)]
    pub(crate) user: Option<String>,

    #[arg(short = 'p', long)]
    pub(crate) passwd: Option<String>,

    #[arg(short = 'm', long)]
    pub(crate) mac: Option<String>,

    #[arg(short = 'i', long)]
    pub(crate) imei: Option<String>,

    #[arg(short = 'b', long)]
    pub(crate) bind: Option<String>,

    #[arg(short = 'a', long)]
    pub(crate) address: Option<String>,

    #[arg(short = 'I', long)]
    pub(crate) interface: Option<String>,

    #[arg(short = 'c', long)]
    pub(crate) config: Option<String>,

    #[arg(long)]
    pub(crate) extra_playlist: Vec<String>,

    #[arg(long)]
    pub(crate) extra_xmltv: Vec<String>,

    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub(crate) udp_proxy: bool,

    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub(crate) rtsp_proxy: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct EffectiveArgs {
    pub(crate) user: String,
    pub(crate) passwd: String,
    pub(crate) mac: String,
    pub(crate) imei: String,
    pub(crate) bind: String,
    pub(crate) address: String,
    pub(crate) interface: Option<String>,
    pub(crate) extra_playlist: Vec<String>,
    pub(crate) extra_xmltv: Vec<String>,
    pub(crate) udp_proxy: bool,
    pub(crate) rtsp_proxy: bool,
}
