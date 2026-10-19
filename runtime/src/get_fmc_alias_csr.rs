// Licensed under the Apache-2.0 license

use crate::get_idev_csr::send_csr_resp;
use crate::Drivers;
use caliptra_error::CaliptraResult;

pub struct GetFmcAliasCsrCmd;
impl GetFmcAliasCsrCmd {
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        send_csr_resp(drivers, true)
    }
}
