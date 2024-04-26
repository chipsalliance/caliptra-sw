// Licensed under the Apache-2.0 license

use std::fmt::Write;

use serde::Deserialize;
use serde_xml_rs as serde_xml;

use crate::TestCaseStatus;

#[derive(Debug, Deserialize, PartialEq)]
pub struct TestSuites {
    pub name: String,

    #[serde(default)]
    #[serde(rename = "testsuite")]
    pub test_suites: Vec<TestSuite>,
}
impl TestSuites {
    pub fn from_xml(xml: &str) -> Result<Self, serde_xml::Error> {
        serde_xml_rs::from_str(xml)
    }
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct TestSuite {
    pub name: String,

    #[serde(default)]
    #[serde(rename = "testcase")]
    pub test_cases: Vec<TestCase>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Skipped {
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Error {
    #[serde(rename = "type")]
    #[serde(default)]
    pub ty: String,

    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct TestCase {
    pub name: String,

    pub time: f64,

    #[serde(rename = "system-out")]
    pub system_out: String,

    #[serde(rename = "system-err")]
    pub system_err: String,

    #[serde(default)]
    pub skipped: Option<Skipped>,

    #[serde(default)]
    #[serde(rename = "error")]
    pub errors: Vec<Error>,

    #[serde(default)]
    #[serde(rename = "failure")]
    pub failures: Vec<Error>,
}
impl TestCase {
    pub fn status(&self) -> TestCaseStatus {
        if self.errors.is_empty() && self.failures.is_empty() {
            if self.skipped.is_some() {
                // NOTE: nexttest doesn't seem to use this; ignored tests aren't
                // recorded in the XML at all (but are in the test metadata
                // JSON).
                TestCaseStatus::Ignored
            } else {
                TestCaseStatus::Passed
            }
        } else {
            TestCaseStatus::Failed
        }
    }

    pub fn output_truncated(&self) -> String {
        let mut result = String::new();
        let label_output = !self.system_out.is_empty() && !self.system_err.is_empty();
        if label_output {
            writeln!(&mut result, "stdout:").unwrap();
        }
        write_truncated_output(&mut result, &self.system_out, 12288).unwrap();
        if label_output {
            writeln!(&mut result, "\n\nstderr:").unwrap();
        }
        write_truncated_output(&mut result, &self.system_err, 12288).unwrap();
        result
    }
}

fn write_truncated_output(
    mut w: impl std::fmt::Write,
    s: &str,
    max_size: usize,
) -> std::fmt::Result {
    if s.len() > max_size {
        writeln!(w, "Truncated {} bytes from beginning", s.len() - max_size)?;
        w.write_str(&s[(s.len() - max_size)..])
    } else {
        w.write_str(s)
    }
}
