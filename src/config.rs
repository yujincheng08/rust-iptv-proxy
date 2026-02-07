use anyhow::Result;
use handlebars::Handlebars;
use regex_lite::Regex;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[derive(Default)]
pub(crate) struct Config {
    pub(crate) app: AppConfig,
    pub(crate) alias: AliasConfig,
    pub(crate) resolution: ResolutionConfig,
    pub(crate) groups: GroupConfig,
    pub(crate) sorting: SortingConfig,
    pub(crate) template: TemplateConfig,
    pub(crate) auth: AuthConfig,
    pub(crate) manage: ManageConfig,
    pub(crate) xmltv: XmltvConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[derive(Default)]
pub(crate) struct AppConfig {
    pub(crate) user: Option<String>,
    pub(crate) passwd: Option<String>,
    pub(crate) mac: Option<String>,
    pub(crate) imei: Option<String>,
    pub(crate) bind: Option<String>,
    pub(crate) address: Option<String>,
    pub(crate) interface: Option<String>,
    pub(crate) rtsp_proxy: bool,
    pub(crate) udp_proxy: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct AliasConfig {
    pub(crate) mode: AliasMode,
    pub(crate) rules: Vec<AliasRule>,
}

impl Default for AliasConfig {
    fn default() -> Self {
        Self {
            mode: AliasMode::FirstMatch,
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AliasMode {
    FirstMatch,
    Chain,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AliasRuleType {
    Map,
    Regex,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct AliasRule {
    #[serde(rename = "type")]
    pub(crate) kind: AliasRuleType,
    pub(crate) pattern: String,
    pub(crate) replace: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[derive(Default)]
pub(crate) struct ResolutionConfig {
    pub(crate) default_score: i32,
    pub(crate) rules: Vec<ResolutionRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ResolutionRule {
    pub(crate) pattern: String,
    pub(crate) score: i32,
    pub(crate) label: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct GroupConfig {
    pub(crate) default_group: String,
    pub(crate) entries: Vec<GroupEntry>,
}

impl Default for GroupConfig {
    fn default() -> Self {
        Self {
            default_group: String::from("未分组"),
            entries: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct GroupEntry {
    pub(crate) group: String,
    pub(crate) channels: Option<Vec<String>>,
    pub(crate) match_regex: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct SortingConfig {
    pub(crate) same_alias: Vec<String>,
    pub(crate) prefer_resolution: PreferResolutionConfig,
    pub(crate) source_priority: Vec<String>,
}

impl Default for SortingConfig {
    fn default() -> Self {
        Self {
            same_alias: vec![
                String::from("resolution_desc"),
                String::from("prefer_resolution"),
                String::from("original"),
            ],
            prefer_resolution: PreferResolutionConfig::default(),
            source_priority: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[derive(Default)]
pub(crate) struct PreferResolutionConfig {
    pub(crate) order: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct TemplateConfig {
    pub(crate) extinf: String,
    pub(crate) url: String,
}

impl Default for TemplateConfig {
    fn default() -> Self {
        Self {
            extinf: String::from(
                r#"#EXTINF:-1 tvg-id="{{tvg_id}}" tvg-name="{{alias_name}}" tvg-chno="{{tvg_chno}}"{{catchup_attr}}tvg-logo="{{tvg_logo}}" group-title="{{group}}",{{alias_name}}"#,
            ),
            url: String::from("{{url}}"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct AuthConfig {
    pub(crate) token: String,
    pub(crate) protect: Vec<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            token: String::new(),
            protect: vec![
                String::from("playlist"),
                String::from("xmltv"),
                String::from("manage"),
            ],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[derive(Default)]
pub(crate) struct ManageConfig {
    pub(crate) enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct XmltvConfig {
    pub(crate) use_alias_name: bool,
}

impl Default for XmltvConfig {
    fn default() -> Self {
        Self {
            use_alias_name: true,
        }
    }
}

pub(crate) struct CompiledConfig {
    pub(crate) alias_rules: Vec<CompiledAliasRule>,
    pub(crate) resolution_rules: Vec<CompiledResolutionRule>,
    pub(crate) group_entries: Vec<CompiledGroupEntry>,
}

pub(crate) struct CompiledAliasRule {
    pub(crate) kind: AliasRuleType,
    pub(crate) pattern: String,
    pub(crate) regex: Option<Regex>,
    pub(crate) replace: String,
}

pub(crate) struct CompiledResolutionRule {
    pub(crate) regex: Regex,
    pub(crate) score: i32,
    pub(crate) label: Option<String>,
}

pub(crate) struct CompiledGroupEntry {
    pub(crate) group: String,
    pub(crate) channels: Option<Vec<String>>,
    pub(crate) regex: Option<Regex>,
}

pub(crate) fn load_config(path: Option<&str>) -> Result<Config> {
    let Some(path) = path else {
        return Ok(Config::default());
    };
    let content = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}

pub(crate) fn compile_config(config: &Config) -> Result<CompiledConfig> {
    let mut alias_rules = Vec::new();
    for rule in config.alias.rules.iter() {
        let regex = match rule.kind {
            AliasRuleType::Regex => Some(Regex::new(&rule.pattern)?),
            AliasRuleType::Map => None,
        };
        alias_rules.push(CompiledAliasRule {
            kind: rule.kind.clone(),
            pattern: rule.pattern.clone(),
            regex,
            replace: rule.replace.clone(),
        });
    }

    let mut resolution_rules = Vec::new();
    for rule in config.resolution.rules.iter() {
        resolution_rules.push(CompiledResolutionRule {
            regex: Regex::new(&rule.pattern)?,
            score: rule.score,
            label: rule.label.clone(),
        });
    }

    let mut group_entries = Vec::new();
    for entry in config.groups.entries.iter() {
        let regex = if let Some(pattern) = entry.match_regex.as_ref() {
            Some(Regex::new(pattern)?)
        } else {
            None
        };
        group_entries.push(CompiledGroupEntry {
            group: entry.group.clone(),
            channels: entry.channels.clone(),
            regex,
        });
    }

    Ok(CompiledConfig {
        alias_rules,
        resolution_rules,
        group_entries,
    })
}

pub(crate) fn build_templates(config: &Config) -> Result<Handlebars<'static>> {
    let mut hb = Handlebars::new();
    hb.register_escape_fn(handlebars::no_escape);
    hb.set_strict_mode(false);
    hb.register_template_string("extinf", config.template.extinf.clone())?;
    hb.register_template_string("url", config.template.url.clone())?;
    Ok(hb)
}

pub(crate) fn should_protect(config: &Config, endpoint: &str) -> bool {
    config
        .auth
        .protect
        .iter()
        .any(|e| e.eq_ignore_ascii_case(endpoint))
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ManageTestResult {
    pub(crate) input: String,
    pub(crate) alias_name: String,
    pub(crate) resolution_score: i32,
    pub(crate) resolution_label: String,
    pub(crate) group: String,
}
