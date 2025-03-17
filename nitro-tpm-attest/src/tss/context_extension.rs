//! Custom functions for the TSS context

pub(super) trait ContextExtension {
    /// Find a free handle in the given range
    fn find_free_handle(
        &mut self,
        first_handle: u32,
        last_handle: u32,
    ) -> tss_esapi::Result<Option<tss_esapi::handles::TpmHandle>>;
}

impl ContextExtension for tss_esapi::Context {
    fn find_free_handle(
        &mut self,
        first_handle: u32,
        last_handle: u32,
    ) -> tss_esapi::Result<Option<tss_esapi::handles::TpmHandle>> {
        let tpm_handles = self
            .execute_without_session(|context| {
                context.get_capability(
                    tss_esapi::constants::CapabilityType::Handles,
                    first_handle,
                    last_handle - first_handle + 1,
                )
            })
            .and_then(|(capability_data, _)| match capability_data {
                tss_esapi::structures::CapabilityData::Handles(tpm_handles) => Ok(tpm_handles),
                _ => Err(tss_esapi::Error::WrapperError(
                    tss_esapi::WrapperErrorKind::WrongValueFromTpm,
                )),
            })?
            .into_inner()
            .into_iter()
            .map(u32::from)
            .collect::<std::collections::HashSet<_>>();

        (first_handle..=last_handle)
            .find(|tpm_handle| !tpm_handles.contains(tpm_handle))
            .map(tss_esapi::handles::TpmHandle::try_from)
            .transpose()
    }
}
