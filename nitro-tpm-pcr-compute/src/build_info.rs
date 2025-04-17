/// Mimic the Nitro Enclave build info output
#[derive(serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct BuildInfo {
    measurements: std::collections::BTreeMap<String, String>,
}

impl BuildInfo {
    pub(crate) fn new<Hasher: std::fmt::Debug>(hasher: &Hasher) -> Self {
        Self {
            measurements: std::iter::once(("HashAlgorithm".to_string(), format!("{hasher:?}")))
                .collect(),
        }
    }

    pub(crate) fn add_measurement(&mut self, index: u8, digest: aws_lc_rs::digest::Digest) {
        let digest_hex: String = digest
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        self.measurements.insert(format!("PCR{index}"), digest_hex);
    }
}

impl std::fmt::Display for BuildInfo {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string_pretty(&self).map_err(|_| std::fmt::Error)?;

        write!(formatter, "{json}")
    }
}
