use crate::verity::cryptsetup::setup;
use anyhow::{bail, Result};
use std::{fs::File, os::fd::AsRawFd};

use super::setup::CryptParamsVerity;

pub fn format_device(crypt_params: &CryptParamsVerity) -> Result<()> {
    let hash_device = match File::open(crypt_params.hash_device) {
        Ok(file) => file.as_raw_fd(), // File exists, no need to create
        Err(e) => bail!(
            "Cannot create hash image {} for writing. error = {:?}",
            crypt_params.hash_device,
            e
        ),
    };

    Ok(())
}
