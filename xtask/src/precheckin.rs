// Licensed under the Apache-2.0 license

use anyhow::Result;

pub(crate) fn precheckin() -> Result<()> {
    crate::clippy::clippy()?;
    Ok(())
}
