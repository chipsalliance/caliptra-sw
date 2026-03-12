// Licensed under the Apache-2.0 license

use anyhow::Result;

pub(crate) fn precheckin() -> Result<()> {
    crate::cargo_lock::check_cargo_lock()?;
    crate::format::check_format()?;
    crate::license::check_license_headers()?;
    crate::clippy::clippy()?;
    crate::update_frozen_images::check_frozen_images()?;
    Ok(())
}
