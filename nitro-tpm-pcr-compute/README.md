# NitroTPM PCR Compute

This utility enables you to precompute the NitroTPM Platform Configuration Register (PCR) 4 value based on a Unified Kernel Image (UKI). This is the same PCR value that is included in the attestation document returned by the NitroTPM.
You can use the precomputed PCR value to create AWS KMS key policies that grant or deny key access based on this value.
The utility supports PE/COFF images in standard boot environments.
Measurements are precomputed according to the TCG PC Client Platform Firmware Profile Specification.

## Usage

To precompute measurements:

```console
cargo run --package nitro-tpm-pcr-compute -- --image <UKI.efi>
```

## Output

The utility returns measurements in the following JSON format:

```json
{
  "Measurements": {
    "HashAlgorithm": "SHA384",
    "PCR4": "<hex string>"
  }
}
```

## References

- [TCG PC Client Platform Firmware Profile Specification](https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/)

