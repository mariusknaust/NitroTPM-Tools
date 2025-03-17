#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Tpm(#[from] super::tpm::Error),
    #[error(transparent)]
    TpmManager(#[from] crate::tpm_manager::Error),
}

pub(crate) fn nsm_request(
    tpm_manager: &std::cell::RefCell<crate::TpmManager>,
    message_buffer_index: tss_esapi::handles::NvIndexTpmHandle,
) -> Result<(), Error> {
    tpm_manager
        .borrow_mut()
        .raw()?
        .nsm_request(message_buffer_index)?;

    Ok(())
}
