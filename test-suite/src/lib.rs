// Licensed under the Apache-2.0 license

#[cfg(test)]
mod tests {
    use caliptra_hw_model::{HwModel, InitParams};
    use std::io::stdout;

    #[test]
    fn test_if_fmc_loads() {
        let rom =
            caliptra_builder::build_firmware_rom("caliptra-fmc-test-rom", "caliptra-fmc-test-rom")
                .unwrap();
        let payload = caliptra_builder::build_firmware_rom("caliptra-fmc", "caliptra-fmc").unwrap();
        let mut model = caliptra_hw_model::create(InitParams {
            rom: &rom,
            payload: &payload,
            ..Default::default()
        })
        .unwrap();
        //model.step_until(|m| m.output().exit_requested());
        model.copy_output_until_exit_success(stdout()).unwrap();
    }
}
