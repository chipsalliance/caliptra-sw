# Test Matrix

Retrieve `cargo nextest` results from CI runs and create web view to later be published to [https://chipsalliance.github.io/caliptra-sw/](https://chipsalliance.github.io/caliptra-sw/).

The test matrix runner needs two environment variables set:
- `CPTRA_WWW_OUT`: The output directory for the HTML file generation
- `GITHUB_TOKEN`: A Github token with the proper access rights for the CI results

Optionally, you can set `RUST_LOG=info` to get verbose processing information.

## Example
```sh
GITHUB_TOKEN=$YOUR_SECRET_TOKEN RUST_LOG=info CPTRA_WWW_OUT=/tmp/www cargo run
```