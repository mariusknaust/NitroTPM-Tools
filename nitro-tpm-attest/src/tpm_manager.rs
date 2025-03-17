//! While the TSS is used wherever possible, it is required to interact with the raw TPM device in
//! order to send the NSM vendor command. This means the TSS context (which keeps the TPM device
//! open) has to be closed and recreated afterwards. The TPM manager handles these two modes.

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid TPM device path")]
    InvalidTpmDevicePath,
    #[error(transparent)]
    Tpm(#[from] crate::raw::tpm::Error),
    #[error(transparent)]
    Tss(#[from] tss_esapi::Error),
}

pub(crate) struct TpmManager {
    device_path: std::path::PathBuf,
    mode: Mode,
}

enum Mode {
    Tss(tss_esapi::Context),
    Raw(crate::raw::Tpm),
    None,
}

impl TpmManager {
    pub(crate) fn new(device_path: std::path::PathBuf) -> Self {
        Self {
            device_path,
            mode: Mode::None,
        }
    }

    pub(crate) fn tss(&mut self) -> Result<&mut tss_esapi::Context, Error> {
        match self.mode {
            Mode::Tss(ref mut context) => return Ok(context),
            // Close the raw TPM device
            Mode::Raw(_) => self.mode = Mode::None,
            _ => (),
        }

        let tcti_name_conf = tss_esapi::TctiNameConf::Device(std::str::FromStr::from_str(
            self.device_path
                .as_os_str()
                .to_str()
                .ok_or(Error::InvalidTpmDevicePath)?,
        )?);

        self.mode = Mode::Tss(tss_esapi::Context::new(tcti_name_conf)?);

        Ok(match self.mode {
            Mode::Tss(ref mut context) => context,
            _ => unreachable!(),
        })
    }

    pub(crate) fn raw(&mut self) -> Result<&mut crate::raw::Tpm, Error> {
        match self.mode {
            Mode::Raw(ref mut tpm) => return Ok(tpm),
            // Close the TSS context
            Mode::Tss(_) => self.mode = Mode::None,
            _ => (),
        }

        self.mode = Mode::Raw(crate::raw::Tpm::new(&self.device_path)?);

        Ok(match self.mode {
            Mode::Raw(ref mut tpm_device) => tpm_device,
            _ => unreachable!(),
        })
    }
}
