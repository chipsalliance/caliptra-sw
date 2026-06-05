// Licensed under the Apache-2.0 license

use anyhow::Result;
use google_cloud_aiplatform_v1::client::PredictionService;
use google_cloud_aiplatform_v1::model::{Content, GenerateContentRequest, Part};

#[derive(Debug, Clone, PartialEq)]
pub struct TestInfo {
    pub package: String,
    pub test: String,
}

pub fn get_test_list(profile: &str) -> Result<Vec<TestInfo>> {
    let output = std::process::Command::new("cargo")
        .args([
            "nextest",
            "list",
            "--workspace",
            "--profile",
            profile,
            "--message-format",
            "oneline",
        ])
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "failed to list tests: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut tests = Vec::new();
    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        // Format is: <package_name>[::<target_name>] <test_name>
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let target_info = parts[0];
            let test_name = parts[1];
            let pkg_parts: Vec<&str> = target_info.split("::").collect();
            let package_name = pkg_parts[0];
            tests.push(TestInfo {
                package: package_name.to_string(),
                test: test_name.to_string(),
            });
        }
    }
    Ok(tests)
}

pub async fn run_generate_content(
    project: &str,
    location: &str,
    model: &str,
    prompt: &str,
) -> Result<()> {
    log::info!(
        "Connecting to project {}, location {}, model {}",
        project,
        location,
        model
    );
    log::info!("Prompt: {}", prompt);

    let client = PredictionService::builder().build().await?;

    let endpoint = format!(
        "projects/{}/locations/{}/publishers/google/models/{}",
        project, location, model
    );

    let mut part = Part::default();
    part.data = Some(google_cloud_aiplatform_v1::model::part::Data::Text(
        prompt.to_string(),
    ));

    let mut content = Content::default();
    content.role = "user".to_string();
    content.parts = vec![part];

    let mut request = GenerateContentRequest::default();
    request.model = endpoint;
    request.contents = vec![content];

    let response = client
        .generate_content()
        .with_request(request)
        .send()
        .await?;

    log::info!("Response: {:?}", response);

    Ok(())
}

pub async fn run_generate_nextest_filter(
    project: &str,
    location: &str,
    model: &str,
    branch: &str,
    profile: &str,
) -> Result<()> {
    log::info!("Running git diff against target branch '{}'...", branch);
    let output = std::process::Command::new("git")
        .args(["diff", branch])
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "git diff failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let diff = String::from_utf8_lossy(&output.stdout);
    if diff.trim().is_empty() {
        log::info!(
            "No changes detected between {} and HEAD. Fallback filter: default()",
            branch
        );
        println!("default()");
        return Ok(());
    }

    log::info!("Detected diff length: {} bytes", diff.len());

    log::info!("Retrieving allowed test list for profile '{}'...", profile);
    let test_list = get_test_list(profile)?;
    log::info!("Found {} allowed tests", test_list.len());

    let mut test_list_str = String::new();
    for t in &test_list {
        test_list_str.push_str(&format!("- package: {}, test: {}\n", t.package, t.test));
    }

    log::info!(
        "Requesting nextest filter expression from Vertex AI model {} in project {} (profile: {})...",
        model, project, profile
    );

    let initial_prompt = format!(
        "Analyze the following git diff and determine which specific test functions or test cases are affected.\n\
        You MUST strictly select a subset of tests from the \"Allowed Tests\" list below. Do NOT select any tests that are not in this list.\n\
        The generated filter MUST only match tests that are present in the \"Allowed Tests\" list. It must strictly be a subset of the passed in list and never include more tests.\n\
        Focus on individual tests and do NOT select entire crates or packages.\n\
        For each selected test, generate a filter expression in the format `package(package_name) and test(test_name)`.\n\
        Combine the individual test filters using `or`.\n\
        Example output format: (package(pkg1) and test(test1)) or (package(pkg2) and test(test2))\n\
        Output ONLY the raw nextest filter string without markdown wrapping, quotes, or code blocks. If no tests are relevant, output `none()`.\n\n\
        Allowed Tests:\n{}\n\n\
        Git Diff:\n{}",
        test_list_str,
        diff
    );

    let client = PredictionService::builder().build().await?;
    let endpoint = format!(
        "projects/{}/locations/{}/publishers/google/models/{}",
        project, location, model
    );

    let mut initial_part = Part::default();
    initial_part.data = Some(google_cloud_aiplatform_v1::model::part::Data::Text(
        initial_prompt,
    ));

    let mut initial_content = Content::default();
    initial_content.role = "user".to_string();
    initial_content.parts = vec![initial_part];

    let mut history = vec![initial_content];

    for attempt in 1..=2 {
        let mut request = GenerateContentRequest::default();
        request.model = endpoint.clone();
        request.contents = history.clone();

        log::info!(
            "Sending AI filter generation request (Attempt {} of 2)...",
            attempt
        );
        let response = match client.generate_content().with_request(request).send().await {
            Ok(resp) => resp,
            Err(err) => {
                log::warn!("Attempt {} model generation failed: {}", attempt, err);
                continue;
            }
        };

        let mut candidate_expr = None;
        for candidate in &response.candidates {
            if let Some(content) = &candidate.content {
                for part in &content.parts {
                    if let Some(google_cloud_aiplatform_v1::model::part::Data::Text(text)) =
                        &part.data
                    {
                        if !text.trim().is_empty() {
                            candidate_expr = Some(text.trim().to_string());
                            break;
                        }
                    }
                }
            }
        }

        let expr = match candidate_expr {
            Some(e) => e,
            None => {
                log::warn!("Attempt {} produced no valid candidate expression", attempt);
                continue;
            }
        };

        log::info!(
            "Attempt {} generated filter: '{}'. Verifying with nextest list...",
            attempt,
            expr
        );
        let nextest_res = std::process::Command::new("cargo")
            .args([
                "nextest",
                "list",
                "--workspace",
                "--profile",
                profile,
                "-E",
                &expr,
            ])
            .output();

        match nextest_res {
            Ok(out) if out.status.success() => {
                let matched_output = String::from_utf8_lossy(&out.stdout);
                let matched_count = matched_output
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .count();

                if expr == "none()" || matched_count > 0 {
                    log::info!("Successfully validated filter expression with cargo nextest on attempt {} (matches {} tests)", attempt, matched_count);
                    println!("{}", expr);
                    return Ok(());
                } else {
                    log::warn!(
                        "Attempt {} filter '{}' matched 0 tests (and is not 'none()'). Rejecting.",
                        attempt,
                        expr
                    );

                    if attempt == 2 {
                        break;
                    }

                    let feedback = format!(
                        "The filter expression '{}' matched 0 tests, but it is not 'none()'. \
                        This usually means the test names were misspelled or do not exist in the allowed list. \
                        Please strictly select tests from the allowed list and verify spelling.",
                        expr
                    );

                    record_failure_and_retry(&mut history, &expr, &feedback);
                }
            }
            Ok(out) => {
                let err_msg = String::from_utf8_lossy(&out.stderr);
                log::warn!(
                    "Attempt {} filter '{}' verification failed:\n{}",
                    attempt,
                    expr,
                    err_msg.trim()
                );

                if attempt == 2 {
                    break;
                }

                let feedback = format!(
                    "The filter expression '{}' failed with the following `cargo nextest` error:\n{}\n\
                    Please provide a corrected valid cargo nextest filter expression. Output exactly the raw expression string.",
                    expr,
                    err_msg.trim()
                );

                record_failure_and_retry(&mut history, &expr, &feedback);
            }
            Err(e) => {
                log::warn!(
                    "Attempt {} failed to spawn cargo nextest process: {}",
                    attempt,
                    e
                );
            }
        }
    }

    log::warn!(
        "Filter generation and validation failed after 2 attempts. Falling back to profile default: default()"
    );
    println!("default()");

    Ok(())
}

fn record_failure_and_retry(history: &mut Vec<Content>, expr: &str, feedback: &str) {
    let mut model_part = Part::default();
    model_part.data = Some(google_cloud_aiplatform_v1::model::part::Data::Text(
        expr.to_string(),
    ));

    let mut model_content = Content::default();
    model_content.role = "model".to_string();
    model_content.parts = vec![model_part];
    history.push(model_content);

    let mut user_part = Part::default();
    user_part.data = Some(google_cloud_aiplatform_v1::model::part::Data::Text(
        feedback.to_string(),
    ));

    let mut user_content = Content::default();
    user_content.role = "user".to_string();
    user_content.parts = vec![user_part];
    history.push(user_content);
}
