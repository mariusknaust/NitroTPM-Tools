mod build_info;
mod hasher;
mod pcr;

use anyhow::Context as _;
use build_info::BuildInfo;
use hasher::Hasher;
use pcr::Pcr;

/// Precompute selected TPM PCRs of an unified kernel image (UKI)
#[derive(clap::Parser)]
struct Arguments {
    /// Path of an EFI image file
    ///
    /// When multiple images are provided, the argument order has to match the load order.
    #[arg(long, short)]
    image: Vec<std::path::PathBuf>,
}

fn main() -> anyhow::Result<()> {
    const ALGORITHM: &aws_lc_rs::digest::Algorithm = &aws_lc_rs::digest::SHA384;

    env_logger::init();

    let arguments: Arguments = clap::Parser::parse();
    let images = arguments
        .image
        .iter()
        .map(|path| {
            std::fs::read(path)
                .with_context(|| format!("Could not read image from {}", path.display()))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let images = arguments
        .image
        .iter()
        .zip(images.iter())
        .map(|(path, image)| {
            object::read::pe::PeFile64::parse(image.as_slice())
                .with_context(|| format!("Could not parse 64-bit PE file from {}", path.display()))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut build_info = BuildInfo::new(ALGORITHM);

    build_info.add_measurement(4, pcr4(ALGORITHM, &images)?);

    println!("{build_info}");

    Ok(())
}

/// TCG PC Client Platform Firmware Profile Specification
/// 3.3.4.5 PCR[4] – Boot Manager Code and Boot Attempts
fn pcr4<'a, Image>(
    algorithm: &'static aws_lc_rs::digest::Algorithm,
    images: &'a [Image],
) -> anyhow::Result<aws_lc_rs::digest::Digest>
where
    Image: object::Object<'a> + authenticode::PeTrait,
{
    // Platform Firmware MUST record the EV_EFI_ACTION event “Calling EFI Application from Boot
    // Option”
    let action_hash =
        aws_lc_rs::digest::digest(algorithm, b"Calling EFI Application from Boot Option");

    log::debug!("[PCR4] EV_EFI_ACTION: {action_hash:?}");
    let mut pcr4 = Pcr::new(algorithm, &action_hash);

    // an EV_SEPARATOR event MUST be recorded in the event log for PCR[0-7] prior to the first
    // invocation of the first Ready to Boot call
    let seperator_hash = seperator_hash(algorithm);

    log::debug!("[PCR4] EV_SEPARATOR: {seperator_hash:?}");
    pcr4.extend(&seperator_hash);

    // For the UEFI application code PE/COFF image described by the boot variable, Platform Firmware
    // MUST record the EV_EFI_BOOT_SERVICES_APPLICATION into PCR[4].
    for image in images {
        let image_hash = pe_hash(algorithm, image)?;

        log::debug!("[PCR4] EV_EFI_BOOT_SERVICES_APPLICATION: {image_hash:?}");
        pcr4.extend(&image_hash);

        let linux_section = object::Object::section_by_name(image, ".linux");

        // https://uapi-group.org/specifications/specs/unified_kernel_image/
        // Only the .linux section is required for the image to be considered a Unified Kernel Image
        if let Some(linux_section) = linux_section {
            let stub_major_version = object::Object::section_by_name(image, ".sdmagic")
                .context("Could not find .sdmagic section of UKI")
                .and_then(|sdmagic| {
                    Ok(std::str::from_utf8(object::ObjectSection::data(&sdmagic)?)?
                        .trim_end_matches('\0')
                        .strip_prefix("#### LoaderInfo: systemd-stub ")
                        .and_then(|string| string.strip_suffix(" ####"))
                        .and_then(|version_string| {
                            version_string
                                .split(|character: char| !character.is_ascii_digit())
                                .next()
                        })
                        .context("Unexpected .sdmagic section format")?
                        .parse::<u32>()?)
                })?;
            let skip_kernel_measurement =
                    // https://github.com/systemd/systemd/pull/37372
                    // Systemd-stub version 258 starts to load and run the kernel image directly
                    stub_major_version >= 258;

            if skip_kernel_measurement {
                continue;
            }

            let linux =
                object::read::pe::PeFile64::parse(object::ObjectSection::data(&linux_section)?)
                    .context("Could not parse .linux section as 64-bit PE file")?;
            let linux_hash = pe_hash(algorithm, &linux)?;

            log::debug!("[PCR4] EV_EFI_BOOT_SERVICES_APPLICATION: {linux_hash:?}");
            pcr4.extend(&linux_hash);
        }
    }

    Ok(pcr4.into())
}

fn seperator_hash(algorithm: &'static aws_lc_rs::digest::Algorithm) -> aws_lc_rs::digest::Digest {
    aws_lc_rs::digest::digest(algorithm, &[0u8; 4])
}

fn pe_hash(
    algorithm: &'static aws_lc_rs::digest::Algorithm,
    pe: &dyn authenticode::PeTrait,
) -> anyhow::Result<aws_lc_rs::digest::Digest> {
    let mut hasher = Hasher::new(algorithm);

    authenticode::authenticode_digest(pe, &mut hasher)?;

    Ok(hasher.finalize())
}
