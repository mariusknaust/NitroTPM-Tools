#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Tpm(#[from] super::tpm::Error),
    #[error(transparent)]
    TpmManager(#[from] crate::tpm_manager::Error),
    #[error(transparent)]
    Tss(#[from] tss_esapi::Error),
    #[error(transparent)]
    AwsLc(#[from] aws_lc_rs::error::Unspecified),
}

pub(super) struct AuthSession<'a> {
    tpm_manager: &'a std::cell::RefCell<crate::TpmManager>,
    session_handle: tss_esapi::handles::TpmHandle,
    session_key: [u8; 512 / 8],
}

impl<'a> AuthSession<'a> {
    /// Creates a new authorization session and returns the initial TPM nonce alongside it
    pub(crate) fn new(
        tpm_manager: &'a std::cell::RefCell<crate::TpmManager>,
        salt_key_handle: tss_esapi::handles::TpmHandle,
        salt_public_encryption_key: &aws_lc_rs::rsa::PublicEncryptingKey,
    ) -> Result<(Self, tss_esapi::structures::Nonce), Error> {
        let mut nonce_caller = [0u8; tss_esapi::structures::Nonce::MAX_SIZE];
        // Size according to the salt key name hash algorithm
        let mut salt = [0u8; 256 / 8];

        aws_lc_rs::rand::fill(&mut nonce_caller)?;
        aws_lc_rs::rand::fill(&mut salt)?;

        let nonce_caller = tss_esapi::structures::Nonce::try_from(nonce_caller.as_slice())?;
        let encrypted_salt = encrypt_salt(salt_public_encryption_key, &salt)?;

        let (session_handle, nonce_tpm) = tpm_manager.borrow_mut().raw()?.start_auth_session(
            Some((salt_key_handle, &encrypted_salt)),
            None,
            &nonce_caller,
            tss_esapi::constants::session_type::SessionType::Hmac,
            tss_esapi::structures::SymmetricDefinition::Null,
            tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha512,
        )?;
        let session_key = derive_session_key(&salt, &nonce_tpm, &nonce_caller)?;

        Ok((
            Self {
                tpm_manager,
                session_handle,
                session_key,
            },
            nonce_tpm,
        ))
    }

    pub(crate) fn auth_area(
        &self,
        auth_value: &tss_esapi::structures::Auth,
        nonce_tpm: &tss_esapi::structures::Nonce,
        cp_hash: &tss_esapi::structures::Digest,
    ) -> Result<Vec<u8>, Error> {
        let mut nonce_caller = [0u8; tss_esapi::structures::Nonce::MAX_SIZE];

        aws_lc_rs::rand::fill(&mut nonce_caller)?;

        let nonce_caller = tss_esapi::structures::Nonce::try_from(nonce_caller.as_slice())?;

        let (session_attributes, _) = tss_esapi::attributes::session::SessionAttributes::builder()
            // We manage the session ourselves, so we can also flush it when an error occurs
            .with_continue_session(true)
            .build();
        let session_attributes = tss_esapi::tss2_esys::TPMA_SESSION::from(session_attributes);

        let auth_hmac = auth_hmac(
            &self.session_key,
            auth_value,
            cp_hash,
            &nonce_caller,
            nonce_tpm,
            session_attributes,
        );
        let auth_hmac = auth_hmac.as_ref();

        Ok([
            u32::from(self.session_handle).to_be_bytes().as_slice(),
            &(nonce_caller.len() as u16).to_be_bytes(),
            &nonce_caller,
            &session_attributes.to_be_bytes(),
            &(auth_hmac.len() as u16).to_be_bytes(),
            auth_hmac,
        ]
        .concat())
    }
}

impl Drop for AuthSession<'_> {
    fn drop(&mut self) {
        self.tpm_manager
            .borrow_mut()
            .raw()
            .expect("Could not get TPM device")
            .flush_context(self.session_handle)
            .expect("Could not flush auth session");
    }
}

// B.10.2 RSA Encryption of Salt
fn encrypt_salt(
    salt_public_encryption_key: &aws_lc_rs::rsa::PublicEncryptingKey,
    salt: &[u8; 256 / 8],
) -> Result<tss_esapi::structures::EncryptedSecret, Error> {
    let salt_public_encryption_key =
        aws_lc_rs::rsa::OaepPublicEncryptingKey::new(salt_public_encryption_key.clone())?;
    let mut encrypted_salt = vec![0u8; salt_public_encryption_key.ciphertext_size()];

    salt_public_encryption_key.encrypt(
        &aws_lc_rs::rsa::OAEP_SHA256_MGF1SHA256,
        salt,
        &mut encrypted_salt,
        Some(b"SECRET\0"),
    )?;

    Ok(encrypted_salt.try_into()?)
}

// 19.6.11 Salted Session Key Generation
fn derive_session_key(
    salt: &[u8],
    nonce_tpm: &tss_esapi::structures::Nonce,
    nonce_caller: &tss_esapi::structures::Nonce,
) -> Result<[u8; 512 / 8], aws_lc_rs::error::Unspecified> {
    const ALGORITHM: &aws_lc_rs::kdf::KbkdfCtrHmacAlgorithm =
        aws_lc_rs::kdf::get_kbkdf_ctr_hmac_algorithm(
            aws_lc_rs::kdf::KbkdfCtrHmacAlgorithmId::Sha512,
        )
        .expect("Algorithm not usable with the configured crate feature set");

    let info = [
        b"ATH\0",
        nonce_tpm.as_slice(),
        nonce_caller.as_slice(),
        &512u32.to_be_bytes(),
    ]
    .concat();
    let mut session_key = [0u8; 512 / 8];

    aws_lc_rs::kdf::kbkdf_ctr_hmac(ALGORITHM, salt, &info, &mut session_key)?;

    Ok(session_key)
}

// 19.6.11 Salted Session Key Generation
fn auth_hmac(
    session_key: &[u8],
    auth_value: &tss_esapi::structures::Auth,
    cp_hash: &tss_esapi::structures::Digest,
    nonce_caller: &tss_esapi::structures::Nonce,
    nonce_tpm: &tss_esapi::structures::Nonce,
    session_attributes: tss_esapi::tss2_esys::TPMA_SESSION,
) -> aws_lc_rs::hmac::Tag {
    let hmac_key = aws_lc_rs::hmac::Key::new(
        aws_lc_rs::hmac::HMAC_SHA512,
        &[session_key, auth_value].concat(),
    );
    let mut signer = aws_lc_rs::hmac::Context::with_key(&hmac_key);

    signer.update(cp_hash.value());
    signer.update(nonce_caller);
    signer.update(nonce_tpm);
    signer.update(&[session_attributes]);

    signer.sign()
}
