// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Abstraction for the TPM2 AWS NSM Vendor Command
//!
//! Provides a high-level interface for the TPM2 AWS vendor command that is used to send NSM
//! attestation requests.
//!
//! Everything goes through the kernel resource manager, which admits many users at a time, so a
//! concurrent invocation cannot take the TPM away mid-request. Only the vendor command can be
//! refused there, because a kernel before 6.3 masks the vendor bit off the command codes the TPM
//! reports and so never matches one, and the tool then falls back to the TPM device, which
//! admits a single user. Both paths are configurable through TPM_RESOURCE_MANAGER_DEVICE and
//! TPM_DEVICE.

pub mod raw;
pub mod tss;

use tss::ContextExtension as _;

pub use aws_nitro_enclaves_nsm_api::api as nsm_api;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(
        "an attestation document takes up to {required} bytes, but the TPM holds at most \
         {available} per NV index, so EC2 instance attestation is not supported on this TPM"
    )]
    NvIndexSizeInsufficient { required: usize, available: usize },
    #[error(
        "the {parameter} is larger than the {} bytes the NSM accepts",
        tss::message_buffer::PARAMETER_MAX_SIZE
    )]
    ParameterTooLarge { parameter: &'static str },
    #[error("the owner authorization value is longer than the TPM accepts")]
    OwnerAuthTooLong,
    #[error("invalid NSM response")]
    InvalidNsmResponse,
    #[error("NSM error response: {0:?}")]
    NsmErrorResponse(nsm_api::ErrorCode),
    #[error(transparent)]
    Open(#[from] OpenError),
    #[error(transparent)]
    MessageBuffer(#[from] tss::message_buffer::Error),
    #[error(transparent)]
    NsmRequest(#[from] raw::Error),
    #[error(transparent)]
    Tss(#[from] tss_esapi::Error),
}

impl Error {
    /// Whether another attestation held what this one needed, so that a later attempt can succeed
    /// once that one released it
    ///
    /// An attestation holds an NV index for its duration, and it holds the TPM device itself where
    /// the resource manager does not carry the vendor command. A TPM has little NV memory to spare
    /// and the device admits a single user, so attestations running next to each other run out of
    /// both. Retrying is left to the caller, which knows how long it can afford to wait, but it takes
    /// this to tell the case apart from a failure that will not pass.
    #[must_use]
    pub fn is_temporarily_unavailable(&self) -> bool {
        // The device is exclusive, so a concurrent attestation holding it is reported as busy
        if let Self::Open(OpenError {
            source: OpenErrorKind::Tpm(raw::Error::Io(error)),
            ..
        }) = self
        {
            return error.kind() == std::io::ErrorKind::ResourceBusy;
        }

        matches!(
            self,
            Self::MessageBuffer(tss::message_buffer::Error::Tss(
                tss_esapi::Error::Tss2Error(response_code)
            ))
            | Self::Tss(tss_esapi::Error::Tss2Error(response_code))
                if response_code.kind()
                    == Some(tss_esapi::constants::response_code::Tss2ResponseCodeKind::NvSpace)
        )
    }

    /// Whether a transport rejected the vendor command as unsupported, without the TPM seeing it
    fn is_unsupported_command(&self) -> bool {
        let Self::NsmRequest(raw::Error::TpmErrorResponse(response_code)) = self else {
            return false;
        };

        response_code.kind()
            == Some(tss_esapi::constants::response_code::Tss2ResponseCodeKind::CommandCode)
    }
}

/// Failure of opening a TPM transport, naming the device it was opened on
#[derive(thiserror::Error, Debug)]
#[error("could not open the TPM device {device_path:?}")]
pub struct OpenError {
    device_path: std::path::PathBuf,
    source: OpenErrorKind,
}

impl OpenError {
    /// Path of the TPM device that could not be opened
    #[must_use]
    pub fn device_path(&self) -> &std::path::Path {
        &self.device_path
    }
}

/// Reason a TPM transport could not be opened
#[derive(thiserror::Error, Debug)]
enum OpenErrorKind {
    #[error("the path is not valid Unicode, which the TSS requires")]
    NonUnicodePath,
    #[error(transparent)]
    Tpm(#[from] raw::Error),
    #[error(transparent)]
    Tss(#[from] tss_esapi::Error),
}

/// Request a NitroTPM attestation document, carrying the optional user data, nonce and public key
///
/// A shorthand for an [`AttestationRequest`] that authorizes with a password session, without
/// authenticating the TPM. Use the builder for the more advanced options.
pub fn attestation_document(
    user_data: impl Into<Option<Vec<u8>>>,
    nonce: impl Into<Option<Vec<u8>>>,
    public_key: impl Into<Option<Vec<u8>>>,
) -> Result<Vec<u8>, Error> {
    AttestationRequest::new()
        .user_data(user_data)?
        .nonce(nonce)?
        .public_key(public_key)?
        .issue()
}

/// A NitroTPM attestation document request, built up from its optional parts
#[derive(Default)]
#[must_use = "the request does nothing until `issue` is called"]
pub struct AttestationRequest {
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    // Held as an Auth, whose buffer is wiped on drop
    owner_auth: Option<tss_esapi::structures::Auth>,
}

impl AttestationRequest {
    /// A request carrying none of the optional parts
    pub fn new() -> Self {
        Self::default()
    }

    /// User data to include in the attestation document
    ///
    /// Errors on a value larger than the NSM accepts, rejecting it here rather than at the request.
    pub fn user_data(mut self, user_data: impl Into<Option<Vec<u8>>>) -> Result<Self, Error> {
        self.user_data = Self::accept_attestation_parameter(user_data.into(), "user data")?;

        Ok(self)
    }

    /// Nonce to include in the attestation document
    ///
    /// Errors on a value larger than the NSM accepts, rejecting it here rather than at the request.
    pub fn nonce(mut self, nonce: impl Into<Option<Vec<u8>>>) -> Result<Self, Error> {
        self.nonce = Self::accept_attestation_parameter(nonce.into(), "nonce")?;

        Ok(self)
    }

    /// Public key to include in the attestation document
    ///
    /// Errors on a value larger than the NSM accepts, rejecting it here rather than at the request.
    pub fn public_key(mut self, public_key: impl Into<Option<Vec<u8>>>) -> Result<Self, Error> {
        self.public_key = Self::accept_attestation_parameter(public_key.into(), "public key")?;

        Ok(self)
    }

    /// Accepts an optional attestation parameter only when it is within the size the NSM accepts,
    /// naming it in the error otherwise
    fn accept_attestation_parameter(
        parameter: Option<Vec<u8>>,
        name: &'static str,
    ) -> Result<Option<Vec<u8>>, Error> {
        if parameter
            .as_ref()
            .is_some_and(|parameter| parameter.len() > tss::message_buffer::PARAMETER_MAX_SIZE)
        {
            return Err(Error::ParameterTooLarge { parameter: name });
        }

        Ok(parameter)
    }

    /// Authorization value of the owner hierarchy, which is only needed when one is set on the TPM
    ///
    /// The NV index this holds is defined and undefined under the owner hierarchy, so a TPM whose
    /// owner authorization is not empty rejects those without it. The value travels to the TPM in
    /// the clear, safe where the wire is not observable.
    ///
    /// Errors on a value longer than the TPM accepts for an authorization value, rejecting it here
    /// rather than at the request. It is held in an [`Auth`](tss_esapi::structures::Auth), which
    /// wipes its buffer on drop.
    pub fn owner_auth(mut self, owner_auth: impl Into<Option<Vec<u8>>>) -> Result<Self, Error> {
        self.owner_auth = owner_auth
            .into()
            .map(tss_esapi::structures::Auth::try_from)
            .transpose()
            .map_err(|_| Error::OwnerAuthTooLong)?;

        Ok(self)
    }

    /// Request the attestation document from the NitroTPM
    pub fn issue(self) -> Result<Vec<u8>, Error> {
        let Self {
            user_data,
            nonce,
            public_key,
            owner_auth,
        } = self;
        let nsm_request = nsm_api::Request::Attestation {
            user_data: user_data.map(Into::into),
            nonce: nonce.map(Into::into),
            public_key: public_key.map(Into::into),
        };

        let tpm_device_path = std::path::PathBuf::from(
            std::env::var_os("TPM_DEVICE").unwrap_or_else(|| "/dev/tpm0".into()),
        );
        let tpm_resource_manager_device_path = std::path::PathBuf::from(
            std::env::var_os("TPM_RESOURCE_MANAGER_DEVICE")
                // An empty variable would take the TSS to /dev/tpm0 and open nothing at all for the
                // vendor command, instead of both going through the resource manager
                .filter(|path| !path.is_empty())
                .unwrap_or_else(|| "/dev/tpmrm0".into()),
        );
        let mut context = tpm_resource_manager_device_path
            .to_str()
            .ok_or(OpenErrorKind::NonUnicodePath)
            .and_then(|path| {
                Ok(tss_esapi::Context::new(tss_esapi::TctiNameConf::Device(
                    std::str::FromStr::from_str(path)?,
                ))?)
            })
            .map_err(|source| OpenError {
                device_path: tpm_resource_manager_device_path.clone(),
                source,
            })?;

        if let Some(owner_auth) = owner_auth {
            context.tr_set_auth(
                tss_esapi::interface_types::resource_handles::Hierarchy::Owner.into(),
                owner_auth,
            )?;
        }

        let available = context
            .get_tpm_property(tss_esapi::constants::property_tag::PropertyTag::NvIndexMax)?
            .and_then(|nv_index_max| usize::try_from(nv_index_max).ok())
            .ok_or(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::WrongValueFromTpm,
            ))?;

        if available < tss::message_buffer::MAX_SIZE {
            return Err(Error::NvIndexSizeInsufficient {
                required: tss::message_buffer::MAX_SIZE,
                available,
            });
        }

        context.execute_with_password_auth_session(|context| {
            let message_buffer = tss::MessageBuffer::from_request(context, &nsm_request)?;

            let send_nsm_request = |device_path| {
                let mut tpm = raw::Tpm::new(device_path).map_err(|error| OpenError {
                    device_path: device_path.into(),
                    source: error.into(),
                })?;

                Ok::<_, Error>(tpm.nsm_request(message_buffer.index(), message_buffer.auth())?)
            };

            send_nsm_request(&tpm_resource_manager_device_path).or_else(|error| {
                if !error.is_unsupported_command() {
                    return Err(error);
                }

                send_nsm_request(&tpm_device_path)
            })?;

            match message_buffer.into_response()? {
                nsm_api::Response::Attestation { document } => Ok(document),
                nsm_api::Response::Error(error_code) => Err(Error::NsmErrorResponse(error_code)),
                _ => Err(Error::InvalidNsmResponse),
            }
        })
    }
}
