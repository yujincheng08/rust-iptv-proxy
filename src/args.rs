use argh::FromArgs;

#[derive(FromArgs, Clone)]
pub(crate) struct Args {
    #[argh(option, short = 'u')]
    pub(crate) user: Option<String>,

    #[argh(option, short = 'p')]
    pub(crate) passwd: Option<String>,

    #[argh(option, short = 'm')]
    pub(crate) mac: Option<String>,

    #[argh(option, short = 'i')]
    pub(crate) imei: Option<String>,

    #[argh(option, short = 'b')]
    pub(crate) bind: Option<String>,

    #[argh(option, short = 'a')]
    pub(crate) address: Option<String>,

    #[argh(option, short = 'I')]
    pub(crate) interface: Option<String>,

    #[argh(option, short = 'c')]
    pub(crate) config: Option<String>,

    #[argh(option)]
    pub(crate) extra_playlist: Vec<String>,

    #[argh(option)]
    pub(crate) extra_xmltv: Vec<String>,

    #[argh(switch)]
    pub(crate) udp_proxy: bool,

    #[argh(switch)]
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
