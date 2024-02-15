use argh::FromArgs;

#[derive(FromArgs, Clone)]
pub(crate) struct Args {
    #[argh(option, short = 'u')]
    pub(crate) user: String,

    #[argh(option, short = 'p')]
    pub(crate) passwd: String,

    #[argh(option, short = 'm')]
    pub(crate) mac: String,

    #[argh(option, short = 'i', default = r#"String::from("")"#)]
    pub(crate) imei: String,

    #[argh(option, short = 'b', default = r#"String::from("127.0.0.1:7878")"#)]
    pub(crate) bind: String,

    #[argh(option, short = 'a', default = r#"String::from("")"#)]
    pub(crate) address: String,

    #[argh(option, short = 'I')]
    pub(crate) interface: Option<String>,

    #[argh(option)]
    pub(crate) extra_playlist: Option<String>,

    #[argh(option)]
    pub(crate) extra_xmltv: Option<String>,

    #[argh(switch)]
    pub(crate) udp_proxy: bool,

    #[argh(switch)]
    pub(crate) rtsp_proxy: bool,
}
