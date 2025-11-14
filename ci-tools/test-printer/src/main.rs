// Licensed under the Apache-2.0 license

use serde::Deserialize;
use std::fs;
use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// The path to the junit.xml file
    #[clap(short, long)]
    xml_path: String,
}

#[derive(Debug, Deserialize, Default)]
struct TestSuites {
    #[serde(rename = "testsuite", default)]
    testsuites: Vec<TestSuite>,
}

#[derive(Debug, Deserialize, Default)]
struct TestSuite {
    #[serde(rename = "@name", default)]
    name: String,
    #[serde(rename = "testcase", default)]
    testcases: Vec<TestCase>,
}

#[derive(Debug, Deserialize, Default)]
struct TestCase {
    #[serde(rename = "@name", default)]
    name: String,
    #[serde(rename = "failure", default)]
    failure: Option<Failure>,
    #[serde(rename = "rerunFailure", default)]
    rerun_failures: Vec<RerunFailure>,
}

#[derive(Debug, Deserialize, Default)]
struct Failure {}

#[derive(Debug, Deserialize, Default)]
struct RerunFailure {}

enum TestStatus {
    Passed,
    Failed,
    Retried,
}

fn main() {
    let args = Args::parse();
    let xml = fs::read_to_string(args.xml_path).expect("Unable to read junit.xml");
    let testsuites: TestSuites = quick_xml::de::from_str(&xml).expect("Unable to parse XML");

    println!("| Test Suite | Test | Status |");
    println!("|---|---|---|");

    for suite in testsuites.testsuites {
        for case in suite.testcases {
            let status = if case.failure.is_some() {
                TestStatus::Failed
            } else if !case.rerun_failures.is_empty() {
                TestStatus::Retried
            } else {
                TestStatus::Passed
            };

            let status_icon = match status {
                TestStatus::Passed => "✅",
                TestStatus::Failed => "❌",
                TestStatus::Retried => "🔁",
            };

            println!("| {} | {} | {} |", suite.name, case.name, status_icon);
        }
    }
}
