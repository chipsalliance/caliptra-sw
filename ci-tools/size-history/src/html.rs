// Licensed under the Apache-2.0 license

use std::{cmp::Ordering, fmt::Write, io};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tinytemplate::TinyTemplate;

use crate::{git, SizeRecord, Sizes};

// The GitHub "HTML sanitizer" is incredibly sensitive to whitespace; do not attempt to break newlines.
static TEMPLATE: &str = r#"
<table>
  <tr><th>Commit</th><th>Author</th><th>Commit</th><th>ROM prod size</th><th>ROM with-uart size</th><th>FMC size</th><th>App size</th></tr>
{{ for record in records }}
  <tr>
    <td><a href="https://github.com/chipsalliance/caliptra-sw/commit/{ record.commit.id }">{ record.commit.id | trim_8 }</a></td>
    <td>{ record.commit.author | name_only }</td>
    {{ if record.important }}<td><strong>{ record.commit.title }</strong></td>{{ else }}<td>{ record.commit.title }</td>{{ endif }}
    <td>{{ if record.sizes.rom_size_prod }}{ record.sizes.rom_size_prod.total }&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<br>({ record.sizes.rom_size_prod.delta | delta_format }){{ else }}build error{{ endif }}</td><td>{{ if record.sizes.rom_size_with_uart }}{ record.sizes.rom_size_with_uart.total }&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<br>({ record.sizes.rom_size_with_uart.delta | delta_format }){{ else }}build error{{ endif }}</td><td>{{ if record.sizes.fmc_size_with_uart }}{ record.sizes.fmc_size_with_uart.total }&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<br>({ record.sizes.fmc_size_with_uart.delta | delta_format }){{ else }}build error{{ endif }}</td><td>{{ if record.sizes.app_size_with_uart }}{ record.sizes.app_size_with_uart.total }&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<br>({ record.sizes.app_size_with_uart.delta | delta_format }){{ else }}build error{{ endif }}</td>
  </tr>
{{ endfor }}
</table>

"#;

pub(crate) fn format_records(records: &[SizeRecord]) -> io::Result<String> {
    let mut extended_records = vec![];
    let mut last_sizes = Sizes::default();
    for record in records.iter().rev() {
        let ext_sizes = ExtendedSizes {
            rom_size_prod: ExtendedSizeInfo::from_change(
                last_sizes.rom_size_prod,
                record.sizes.rom_size_prod,
            ),
            rom_size_with_uart: ExtendedSizeInfo::from_change(
                last_sizes.rom_size_with_uart,
                record.sizes.rom_size_with_uart,
            ),
            fmc_size_with_uart: ExtendedSizeInfo::from_change(
                last_sizes.fmc_size_with_uart,
                record.sizes.fmc_size_with_uart,
            ),
            app_size_with_uart: ExtendedSizeInfo::from_change(
                last_sizes.app_size_with_uart,
                record.sizes.app_size_with_uart,
            ),
        };
        let mut ext_record = ExtendedRecord {
            commit: record.commit.clone(),
            important: is_important(&ext_sizes),
            sizes: ext_sizes,
        };
        ext_record.commit.title.truncate(80);
        extended_records.push(ext_record);
        last_sizes.update_from(&record.sizes);
    }
    extended_records.reverse();

    let mut tt = TinyTemplate::new();
    tt.add_formatter("name_only", |val, out| {
        if let Some(s) = val.as_str() {
            out.write_str(name_only(s))?;
        }
        Ok(())
    });
    tt.add_template("index", TEMPLATE).unwrap();
    tt.add_formatter("trim_8", |val, out| {
        if let Some(s) = val.as_str() {
            out.write_str(s.get(..8).unwrap_or(s))?;
        }
        Ok(())
    });
    tt.add_formatter("delta_format", |val, out| {
        if let Value::Number(delta) = val {
            if let Some(delta) = delta.as_i64() {
                match delta.cmp(&0) {
                    Ordering::Greater => write!(out, "🟥 +{delta}")?,
                    Ordering::Less => write!(out, "🟩 {delta}")?,
                    Ordering::Equal => write!(out, "{delta}")?,
                }
            }
        }
        Ok(())
    });

    Ok(tt
        .render(
            "index",
            &TemplateContext {
                records: extended_records,
            },
        )
        .unwrap())
}

fn is_important(sizes: &ExtendedSizes) -> bool {
    fn has_delta(info: &Option<ExtendedSizeInfo>) -> bool {
        info.map(|i| i.delta != 0).unwrap_or(false)
    }
    has_delta(&sizes.rom_size_prod)
        || has_delta(&sizes.rom_size_with_uart)
        || has_delta(&sizes.fmc_size_with_uart)
        || has_delta(&sizes.app_size_with_uart)
}
fn name_only(val: &str) -> &str {
    if let Some((name, _)) = val.split_once('<') {
        name.trim()
    } else {
        val
    }
}

#[derive(Serialize)]
struct TemplateContext {
    records: Vec<ExtendedRecord>,
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
struct ExtendedSizes {
    // If fields are None, there was a problem building the commit
    rom_size_prod: Option<ExtendedSizeInfo>,
    rom_size_with_uart: Option<ExtendedSizeInfo>,
    fmc_size_with_uart: Option<ExtendedSizeInfo>,
    app_size_with_uart: Option<ExtendedSizeInfo>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
struct ExtendedRecord {
    commit: git::CommitInfo,
    important: bool,
    sizes: ExtendedSizes,
}
