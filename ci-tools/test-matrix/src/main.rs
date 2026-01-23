// Licensed under the Apache-2.0 license

use std::{
    collections::BTreeMap,
    error::Error,
    io::{Cursor, Read},
    path::Path,
};

use nextest_metadata::TestListSummary;
use octocrab::{
    etag::Etagged, models::workflows::Run, params::actions::ArchiveFormat, Octocrab, Page,
};
use serde::Serialize;
use zip::result::ZipError;

mod html;
mod junit;
use log;

const ORG: &str = "chipsalliance";
const REPO: &str = "caliptra-sw";
const NUM_RUNS: usize = 6;

// const WORKFLOW_FILE: &str = "nightly-release-1.x.yml";
const WORKFLOW_FILE: &str = "nightly-release.yml";

async fn all_items<T: for<'de> serde::de::Deserialize<'de>>(
    octocrab: &Octocrab,
    etagged: Etagged<Page<T>>,
) -> Result<Vec<T>, octocrab::Error> {
    let mut result = vec![];
    let Some(mut page) = etagged.value else {
        panic!("etagged.value was not set; using api incorrectly?");
    };
    loop {
        result.extend(page.items);
        page = match octocrab.get_page(&page.next).await? {
            Some(next_page) => next_page,
            None => break,
        }
    }
    Ok(result)
}

fn zip_extract_file(
    zip: &mut zip::ZipArchive<Cursor<&[u8]>>,
    name: &str,
) -> Result<Vec<u8>, ZipError> {
    let mut result = vec![];
    zip.by_name(name)?.read_to_end(&mut result)?;
    Ok(result)
}

#[derive(Debug, serde::Serialize)]
pub struct TestMatrix {
    pub rows: Vec<TestSuite>,
    pub columns: Vec<String>,
}

fn get_at_index_mut<T: Default>(vec: &mut Vec<T>, index: usize) -> &mut T {
    if index >= vec.len() {
        vec.resize_with(index + 1, Default::default);
    }
    &mut vec[index]
}

#[derive(Debug, serde::Serialize)]
pub struct TestSuite {
    pub name: String,
    pub rows: Vec<TestCaseRow>,
}

impl TestMatrix {
    fn new(mut runs: Vec<TestRun>) -> Result<Self, Box<dyn Error + 'static>> {
        runs.sort_by(|a, b| a.name.cmp(&b.name));
        let mut columns = vec![];
        let mut row_map: BTreeMap<String, BTreeMap<String, TestCaseRow>> = BTreeMap::new();
        let runs_len = runs.len();
        for (run_index, run) in runs.into_iter().enumerate() {
            columns.push(run.name);
            for (suite_name, suite) in run.test_list.rust_suites {
                let suite_map = row_map.entry(suite_name.to_string()).or_default();
                for (test_case_name, test_case) in suite.test_cases {
                    let row =
                        suite_map
                            .entry(test_case_name.clone())
                            .or_insert_with(|| TestCaseRow {
                                name: test_case_name,
                                cells: vec![None; runs_len],
                            });
                    *get_at_index_mut(&mut row.cells, run_index) = Some(TestCaseCell {
                        status: if test_case.ignored {
                            TestCaseStatus::Ignored
                        } else {
                            TestCaseStatus::Unknown
                        },
                        output: Default::default(),
                        duration: Default::default(),
                    });
                }
            }
            for suite in run.junit_suites.test_suites {
                let suite_map = row_map
                    .get_mut(&suite.name)
                    .ok_or_else(|| format!("Unknown suite in junit file: {}", suite.name))?;
                for test_case in suite.test_cases {
                    let row = suite_map.get_mut(&test_case.name).ok_or_else(|| {
                        format!("Unknown test-case in junit file: {}", test_case.name)
                    })?;
                    let cell = get_at_index_mut(&mut row.cells, run_index)
                        .as_mut()
                        .ok_or_else(|| {
                            format!(
                                "Unknown test-case for this run in junit file: {}",
                                test_case.name
                            )
                        })?;
                    cell.status = test_case.status();
                    cell.output = test_case.output_truncated();
                    cell.duration = test_case.time;
                }
            }
        }
        let rows: Vec<_> = row_map
            .into_iter()
            .map(|(name, rows)| TestSuite {
                name,
                rows: rows.into_values().collect(),
            })
            .collect();
        Ok(Self { rows, columns })
    }
}

#[derive(Debug, Default, serde::Serialize)]
pub struct TestCaseRow {
    pub name: String,
    pub cells: Vec<Option<TestCaseCell>>,
}

#[derive(Copy, Clone, Debug, serde::Serialize)]
pub enum TestCaseStatus {
    Passed,
    Failed,
    Ignored,
    Unknown,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TestCaseCell {
    pub status: TestCaseStatus,
    pub output: String,
    pub duration: f64,
}

struct TestRun {
    name: String,

    // The metadata about the tests to run (includes tests that were ignored)
    test_list: TestListSummary,

    // The results of the tests that were run (doesn't include ignored tests)
    junit_suites: junit::TestSuites,
}

impl TestRun {
    fn from_zip_bytes(name: String, bytes: &[u8]) -> Result<TestRun, Box<dyn Error>> {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;

        // .github/workflows/{fpga, fpga-subsystem}.yml do not adhere to the naming convention here,
        // since they need to take the matrix partition into account:
        // cargo-nextest [...] \
        //     --message-format json > /tmp/nextest-list-${{ matrix.partition }}.json
        let json_filename = archive
            .file_names()
            .find(|f| f.starts_with("nextest-list") && f.ends_with(".json"))
            .ok_or("No nextest-list*.json file found in zip archive")?
            .to_string();

        let json = zip_extract_file(&mut archive, &json_filename)
            .map_err(|e| format!("Failed to extract {}: {}", json_filename, e))?;

        let json = String::from_utf8(json)?;
        let test_list = nextest_metadata::TestListSummary::parse_json(json)
            .map_err(|e| format!("Failed to parse {}: {}", json_filename, e))?;
        log::info!(
            "{}/{}: {} suites",
            name,
            json_filename,
            test_list.test_count
        );

        let xml_name = archive
            .file_names()
            .find(|f| f.starts_with("junit") && f.ends_with(".xml"))
            .ok_or("No junit.xml file found in zip archive")?
            .to_string();

        let junit_xml = String::from_utf8(
            zip_extract_file(&mut archive, &xml_name)
                .map_err(|e| format!("Failed to extract {}: {}", xml_name, e))?,
        )?;
        let junit_suites = junit::TestSuites::from_xml(&junit_xml)
            .map_err(|e| format!("Failed to parse {}: {}", xml_name, e))?;
        log::info!(
            "{}/{}: {} suites",
            name,
            xml_name,
            junit_suites.test_suites.len()
        );

        Ok(TestRun {
            name,
            test_list,
            junit_suites,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RunInfo {
    pub id: String,
    pub display_name: String,
}
impl RunInfo {
    fn from_run(run: &Run) -> Self {
        RunInfo {
            id: run.created_at.format("%F-%H%M%S").to_string(),
            display_name: run.created_at.format("%F %H:%M:%S").to_string(),
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let www_out = std::env::var("CPTRA_WWW_OUT")
        .expect("CPTRA_WWW_OUT env variable is required (directory to write html)");
    let token = std::env::var("GITHUB_TOKEN").expect("GITHUB_TOKEN env variable is required");

    let octocrab = Octocrab::builder().personal_token(token).build()?;
    let release_runs = octocrab
        .workflows(ORG, REPO)
        .list_runs(WORKFLOW_FILE)
        .branch("main")
        .send()
        .await?;
    log::info!("{}/{}:{}", ORG, REPO, WORKFLOW_FILE);

    let run_infos: Vec<RunInfo> = release_runs
        .items
        .iter()
        .take(NUM_RUNS)
        .map(RunInfo::from_run)
        .collect();

    for (index, run) in release_runs.into_iter().take(NUM_RUNS).enumerate() {
        let artifacts = all_items(
            &octocrab,
            octocrab
                .actions()
                .list_workflow_run_artifacts(ORG, REPO, run.id)
                .send()
                .await?,
        )
        .await?;
        let mut test_runs = vec![];
        for artifact in artifacts {
            if artifact.name.starts_with("caliptra-test-results") {
                let test_run_name = &artifact.name["caliptra-test-results-".len()..];
                let artifact_zip = octocrab
                    .actions()
                    .download_artifact(ORG, REPO, artifact.id, ArchiveFormat::Zip)
                    .await?;

                let t = TestRun::from_zip_bytes(test_run_name.into(), &artifact_zip);
                match t {
                    Ok(test_run) => test_runs.push(test_run),
                    Err(e) => log::error!(
                        "Error processing test results for run {} artifact {}: {}",
                        run.id,
                        artifact.name,
                        e
                    ),
                }
            }
        }
        let matrix = TestMatrix::new(test_runs).unwrap();
        let html = html::format(&run, &run_infos, &matrix);
        std::fs::write(
            Path::new(&www_out).join(format!("run-{}.html", RunInfo::from_run(&run).id)),
            &html,
        )
        .unwrap();
        log::info!("{}/run-{}.html", www_out, RunInfo::from_run(&run).id);

        if index == 0 {
            std::fs::write(Path::new(&www_out).join("index.html"), &html).unwrap();
        }
    }

    Ok(())
}
