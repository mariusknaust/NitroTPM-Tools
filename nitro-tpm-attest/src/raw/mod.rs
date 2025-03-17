//! Encapsulates all raw TPM operations

pub mod nsm_request;
pub mod tpm;

pub(crate) use nsm_request::nsm_request;
pub(crate) use tpm::Tpm;
