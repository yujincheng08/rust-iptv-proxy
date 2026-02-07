use crate::config::{AliasMode, AliasRuleType, CompiledConfig, Config, SortingConfig};
use anyhow::Result;
use handlebars::Handlebars;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChannelEntry {
    pub(crate) key: String,
    pub(crate) source: String,
    pub(crate) channel_id: Option<u64>,
    pub(crate) url: String,
    pub(crate) raw_name: String,
    pub(crate) alias_name: String,
    pub(crate) group: String,
    pub(crate) tvg_id: String,
    pub(crate) tvg_name: String,
    pub(crate) tvg_logo: String,
    pub(crate) tvg_chno: String,
    pub(crate) catchup: String,
    pub(crate) catchup_source: String,
    pub(crate) catchup_attr: String,
    pub(crate) extras: BTreeMap<String, String>,
    pub(crate) resolution_score: i32,
    pub(crate) resolution_label: String,
    pub(crate) original_index: usize,
}

pub(crate) struct EntryBuildContext<'a> {
    pub(crate) config: &'a Config,
    pub(crate) compiled: &'a CompiledConfig,
}

pub(crate) fn apply_alias(name: &str, config: &Config, compiled: &CompiledConfig) -> String {
    let mut current = name.to_string();
    match config.alias.mode {
        AliasMode::FirstMatch => {
            for rule in compiled.alias_rules.iter() {
                match rule.kind {
                    AliasRuleType::Map => {
                        if current == rule.pattern {
                            return rule.replace.clone();
                        }
                    }
                    AliasRuleType::Regex => {
                        if let Some(re) = rule.regex.as_ref()
                            && re.is_match(&current)
                        {
                            return re.replace_all(&current, rule.replace.as_str()).to_string();
                        }
                    }
                }
            }
            current
        }
        AliasMode::Chain => {
            for rule in compiled.alias_rules.iter() {
                match rule.kind {
                    AliasRuleType::Map => {
                        if current == rule.pattern {
                            current = rule.replace.clone();
                        }
                    }
                    AliasRuleType::Regex => {
                        if let Some(re) = rule.regex.as_ref()
                            && re.is_match(&current)
                        {
                            current = re.replace_all(&current, rule.replace.as_str()).to_string();
                        }
                    }
                }
            }
            current
        }
    }
}

pub(crate) fn infer_resolution(
    raw: &str,
    config: &Config,
    compiled: &CompiledConfig,
) -> (i32, String) {
    for rule in compiled.resolution_rules.iter() {
        if rule.regex.is_match(raw) {
            return (
                rule.score,
                rule.label.clone().unwrap_or_else(|| "Unknown".to_string()),
            );
        }
    }
    (config.resolution.default_score, "Unknown".to_string())
}

pub(crate) fn parse_m3u_playlist(
    content: &str,
    source: &str,
    start_index: usize,
) -> Vec<ChannelEntry> {
    let mut entries = Vec::new();
    let mut lines = content.lines();
    let mut index = start_index;
    while let Some(line) = lines.next() {
        let line = line.trim();
        if !line.starts_with("#EXTINF") {
            continue;
        }
        let Some((attrs, name)) = parse_extinf(line) else {
            continue;
        };
        let url = match lines.next() {
            Some(u) => u.trim().to_string(),
            None => break,
        };
        let raw_name = if name.is_empty() {
            attrs
                .get("tvg-name")
                .cloned()
                .unwrap_or_else(|| "Unknown".to_string())
        } else {
            name
        };
        let mut extras = BTreeMap::new();
        for (k, v) in attrs.iter() {
            if k != "tvg-id"
                && k != "tvg-name"
                && k != "tvg-logo"
                && k != "tvg-chno"
                && k != "group-title"
                && k != "catchup"
                && k != "catchup-source"
            {
                extras.insert(k.clone(), v.clone());
            }
        }
        let catchup = attrs.get("catchup").cloned().unwrap_or_default();
        let catchup_source = attrs.get("catchup-source").cloned().unwrap_or_default();
        let catchup_attr = build_catchup_attr(&attrs);
        let key = build_key(source, &url, index);
        entries.push(ChannelEntry {
            key,
            source: source.to_string(),
            channel_id: None,
            url,
            raw_name,
            alias_name: String::new(),
            group: attrs
                .get("group-title")
                .cloned()
                .unwrap_or_else(String::new),
            tvg_id: attrs.get("tvg-id").cloned().unwrap_or_default(),
            tvg_name: attrs.get("tvg-name").cloned().unwrap_or_default(),
            tvg_logo: attrs.get("tvg-logo").cloned().unwrap_or_default(),
            tvg_chno: attrs.get("tvg-chno").cloned().unwrap_or_default(),
            catchup,
            catchup_source,
            catchup_attr,
            extras,
            resolution_score: 0,
            resolution_label: "Unknown".to_string(),
            original_index: index,
        });
        index += 1;
    }
    entries
}

fn parse_extinf(line: &str) -> Option<(BTreeMap<String, String>, String)> {
    let line = line.trim_start_matches("#EXTINF:");
    let mut parts = line.splitn(2, ',');
    let head = parts.next()?.trim();
    let name = parts.next().unwrap_or("").trim().to_string();

    let attrs = parse_attributes(head);
    Some((attrs, name))
}

fn parse_attributes(head: &str) -> BTreeMap<String, String> {
    let mut attrs = BTreeMap::new();
    let mut i = 0usize;
    let bytes = head.as_bytes();
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let key_start = i;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'-')
        {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let key = &head[key_start..i];
        if !head[i..].starts_with("=\"") {
            i += 1;
            continue;
        }
        i += 2;
        let val_start = i;
        while i < bytes.len() && bytes[i] != b'"' {
            i += 1;
        }
        if i > val_start && i <= bytes.len() {
            let val = &head[val_start..i];
            attrs.insert(key.to_string(), val.to_string());
        }
        if i < bytes.len() {
            i += 1;
        }
    }
    attrs
}

fn build_catchup_attr(attrs: &BTreeMap<String, String>) -> String {
    match (attrs.get("catchup"), attrs.get("catchup-source")) {
        (Some(catchup), Some(source)) => {
            format!(r#" catchup="{}" catchup-source="{}" "#, catchup, source)
        }
        _ => String::new(),
    }
}

fn build_key(source: &str, url: &str, index: usize) -> String {
    let digest = format!("{:x}", md5::compute(url.as_bytes()));
    format!("{}:{}:{}", source, digest, index)
}

pub(crate) fn finalize_entries(
    mut entries: Vec<ChannelEntry>,
    ctx: &EntryBuildContext,
) -> Vec<ChannelEntry> {
    for entry in entries.iter_mut() {
        let alias = apply_alias(&entry.raw_name, ctx.config, ctx.compiled);
        let alias = alias.trim().to_string();
        entry.alias_name = if alias.is_empty() {
            entry.raw_name.clone()
        } else {
            alias
        };
        if entry.tvg_name.is_empty() {
            entry.tvg_name = entry.alias_name.clone();
        }
        if entry.tvg_id.is_empty() {
            entry.tvg_id = entry.alias_name.clone();
        }
        let (score, label) = infer_resolution(&entry.raw_name, ctx.config, ctx.compiled);
        entry.resolution_score = score;
        entry.resolution_label = label;
    }
    assign_groups(entries, ctx)
}

fn assign_groups(mut entries: Vec<ChannelEntry>, ctx: &EntryBuildContext) -> Vec<ChannelEntry> {
    if ctx.compiled.group_entries.is_empty() {
        for entry in entries.iter_mut() {
            if entry.group.is_empty() {
                entry.group = ctx.config.groups.default_group.clone();
            }
        }
        return entries;
    }

    let mut remaining = entries;
    let mut output = Vec::new();
    for group_entry in ctx.compiled.group_entries.iter() {
        if let Some(channels) = group_entry.channels.as_ref() {
            for name in channels.iter() {
                let mut picked = Vec::new();
                let mut keep = Vec::new();
                for entry in remaining.into_iter() {
                    if entry.alias_name == *name {
                        let mut e = entry;
                        e.group = group_entry.group.clone();
                        picked.push(e);
                    } else {
                        keep.push(entry);
                    }
                }
                remaining = keep;
                sort_same_alias(&mut picked, &ctx.config.sorting);
                output.extend(picked);
            }
        } else if let Some(regex) = group_entry.regex.as_ref() {
            let mut picked = Vec::new();
            let mut keep = Vec::new();
            for entry in remaining.into_iter() {
                if regex.is_match(&entry.alias_name) {
                    let mut e = entry;
                    e.group = group_entry.group.clone();
                    picked.push(e);
                } else {
                    keep.push(entry);
                }
            }
            remaining = keep;
            sort_by_alias_then_resolution(&mut picked, &ctx.config.sorting);
            output.extend(picked);
        }
    }
    for entry in remaining.iter_mut() {
        entry.group = ctx.config.groups.default_group.clone();
    }
    sort_by_alias_then_resolution(&mut remaining, &ctx.config.sorting);
    output.extend(remaining);
    output
}

fn sort_by_alias_then_resolution(entries: &mut [ChannelEntry], sorting: &SortingConfig) {
    entries.sort_by(|a, b| {
        let name_cmp = a.alias_name.cmp(&b.alias_name);
        if name_cmp != std::cmp::Ordering::Equal {
            return name_cmp;
        }
        compare_same_alias(a, b, sorting)
    });
}

fn sort_same_alias(entries: &mut [ChannelEntry], sorting: &SortingConfig) {
    entries.sort_by(|a, b| compare_same_alias(a, b, sorting));
}

fn compare_same_alias(
    a: &ChannelEntry,
    b: &ChannelEntry,
    sorting: &SortingConfig,
) -> std::cmp::Ordering {
    for rule in sorting.same_alias.iter() {
        match rule.as_str() {
            "prefer_resolution" => {
                let rank_a = resolution_rank(&a.resolution_label, &sorting.prefer_resolution.order);
                let rank_b = resolution_rank(&b.resolution_label, &sorting.prefer_resolution.order);
                let cmp = rank_a.cmp(&rank_b);
                if cmp != std::cmp::Ordering::Equal {
                    return cmp;
                }
            }
            "resolution_desc" => {
                let cmp = b.resolution_score.cmp(&a.resolution_score);
                if cmp != std::cmp::Ordering::Equal {
                    return cmp;
                }
            }
            "source_priority" => {
                let rank_a = source_rank(&a.source, &sorting.source_priority);
                let rank_b = source_rank(&b.source, &sorting.source_priority);
                let cmp = rank_a.cmp(&rank_b);
                if cmp != std::cmp::Ordering::Equal {
                    return cmp;
                }
            }
            "original" => {
                let cmp = a.original_index.cmp(&b.original_index);
                if cmp != std::cmp::Ordering::Equal {
                    return cmp;
                }
            }
            _ => {}
        }
    }
    std::cmp::Ordering::Equal
}

fn resolution_rank(label: &str, order: &[String]) -> usize {
    order
        .iter()
        .position(|v| v.eq_ignore_ascii_case(label))
        .unwrap_or(order.len())
}

fn source_rank(source: &str, order: &[String]) -> usize {
    order
        .iter()
        .position(|v| v.eq_ignore_ascii_case(source))
        .unwrap_or(order.len())
}

pub(crate) fn render_playlist(
    entries: &[ChannelEntry],
    hb: &Handlebars<'static>,
) -> Result<String> {
    let mut lines = Vec::with_capacity(entries.len() * 2 + 1);
    lines.push(String::from("#EXTM3U"));
    for entry in entries.iter() {
        let extinf = hb.render("extinf", entry)?;
        let url = hb.render("url", entry)?;
        lines.push(extinf);
        lines.push(url);
    }
    Ok(lines.join("\n"))
}

pub(crate) fn add_alias_and_resolution_for_name(
    name: &str,
    ctx: &EntryBuildContext,
) -> (String, i32, String) {
    let alias = apply_alias(name, ctx.config, ctx.compiled);
    let (score, label) = infer_resolution(name, ctx.config, ctx.compiled);
    (alias, score, label)
}

pub(crate) fn resolve_group_for_alias(
    alias: &str,
    compiled: &CompiledConfig,
    default_group: &str,
) -> String {
    for entry in compiled.group_entries.iter() {
        if let Some(channels) = entry.channels.as_ref()
            && channels.iter().any(|c| c == alias)
        {
            return entry.group.clone();
        }
        if let Some(regex) = entry.regex.as_ref()
            && regex.is_match(alias)
        {
            return entry.group.clone();
        }
    }
    default_group.to_string()
}
