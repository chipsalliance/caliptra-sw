// Licensed under the Apache-2.0 license

use std::{cmp::Ordering, fmt::Write, io};

use crate::{git::CommitInfo, SizeRecord};

/// Trait for generating reports from size records.
pub trait ReportGenerator {
    fn generate(&self, records: &[SizeRecord], artifact_names: &[&str]) -> io::Result<String>;
}

/// Generates an HTML table report suitable for GitHub step summaries.
pub struct HtmlTableReport {
    /// Base URL for commit links (e.g., "https://github.com/chipsalliance/caliptra-sw")
    pub repo_url: String,
}

impl HtmlTableReport {
    pub fn new(repo_url: impl Into<String>) -> Self {
        Self {
            repo_url: repo_url.into(),
        }
    }
}

impl ReportGenerator for HtmlTableReport {
    fn generate(&self, records: &[SizeRecord], artifact_names: &[&str]) -> io::Result<String> {
        let extended_records = build_extended_records(records, artifact_names);

        let mut html = String::new();
        html.push_str("<table>\n");
        html.push_str("  <tr><th>Commit</th><th>Author</th><th>Commit</th>");

        for name in artifact_names {
            write!(&mut html, "<th>{}</th>", name).unwrap();
        }
        html.push_str("</tr>\n");

        for record in &extended_records {
            html.push_str("  <tr>\n");

            html.write_fmt(core::format_args!(
                "    <td><a href=\"{}/commit/{}\">{}</a></td>\n",
                self.repo_url,
                record.commit.id,
                &record.commit.id[..8.min(record.commit.id.len())]
            ))
            .unwrap();

            html.write_fmt(core::format_args!(
                "    <td>{}</td>\n",
                name_only(&record.commit.author)
            ))
            .unwrap();

            let title = truncate(&record.commit.title, 80);
            if record.important {
                html.write_fmt(core::format_args!(
                    "    <td><strong>{}</strong></td>\n",
                    title
                ))
                .unwrap();
            } else {
                html.write_fmt(core::format_args!("    <td>{}</td>\n", title))
                    .unwrap();
            }

            for name in artifact_names {
                let size_info = record.sizes.get(*name).and_then(|s| s.as_ref());
                match size_info {
                    Some(info) => {
                        html.write_fmt(core::format_args!(
                            "    <td>{}&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<br>({})</td>\n",
                            info.total,
                            format_delta(info.delta)
                        ))
                        .unwrap();
                    }
                    None => {
                        html.push_str("    <td>build error</td>\n");
                    }
                }
            }

            html.push_str("  </tr>\n");
        }

        html.push_str("</table>\n");

        Ok(html)
    }
}

/// Extended size information with delta from previous commit.
#[derive(Clone, Copy)]
struct ExtendedSizeInfo {
    total: u64,
    delta: i64,
}

impl ExtendedSizeInfo {
    fn from_change(prev: Option<u64>, current: Option<u64>) -> Option<Self> {
        let prev = prev.unwrap_or(0);
        current.map(|current| Self {
            total: current,
            delta: current.wrapping_sub(prev) as i64,
        })
    }
}

/// Extended record with computed deltas and importance flag.
struct ExtendedRecord {
    commit: CommitInfo,
    important: bool,
    sizes: std::collections::HashMap<String, Option<ExtendedSizeInfo>>,
}

fn build_extended_records(records: &[SizeRecord], artifact_names: &[&str]) -> Vec<ExtendedRecord> {
    let mut extended_records = vec![];
    let mut last_sizes: std::collections::HashMap<String, Option<u64>> =
        std::collections::HashMap::new();

    for record in records.iter().rev() {
        let mut ext_sizes: std::collections::HashMap<String, Option<ExtendedSizeInfo>> =
            std::collections::HashMap::new();

        for name in artifact_names {
            let current = record.get_size(name);
            let prev = last_sizes.get(*name).copied().flatten();
            ext_sizes.insert(
                name.to_string(),
                ExtendedSizeInfo::from_change(prev, current),
            );

            if current.is_some() {
                last_sizes.insert(name.to_string(), current);
            }
        }

        extended_records.push(ExtendedRecord {
            commit: record.commit.clone(),
            important: is_important(&ext_sizes),
            sizes: ext_sizes,
        });
    }

    // Reverse back to newest-first order
    extended_records.reverse();
    extended_records
}

fn is_important(sizes: &std::collections::HashMap<String, Option<ExtendedSizeInfo>>) -> bool {
    sizes
        .values()
        .any(|info| info.map(|i| i.delta != 0).unwrap_or(false))
}

fn format_delta(delta: i64) -> String {
    match delta.cmp(&0) {
        Ordering::Greater => format!("🟥 +{}", delta),
        Ordering::Less => format!("🟩 {}", delta),
        Ordering::Equal => format!("{}", delta),
    }
}

fn name_only(author: &str) -> &str {
    if let Some((name, _)) = author.split_once('<') {
        name.trim()
    } else {
        author
    }
}

fn truncate(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        s
    } else {
        &s[..max_len]
    }
}
