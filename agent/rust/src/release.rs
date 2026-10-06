//! Offline release verification. No network or installer side effects.
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};
use url::Url;

pub fn require_newer(candidate: &str, installed: &str) -> Result<()> {
    fn parts(value: &str) -> Result<([u64; 3], Option<Vec<&str>>)> {
        let (core, pre) = value
            .split_once('-')
            .map_or((value, None), |(c, p)| (c, Some(p)));
        let core: Vec<_> = core.split('.').collect();
        if core.len() != 3 {
            bail!("version must have three numeric components");
        }
        let mut numbers = [0; 3];
        for (i, part) in core.iter().enumerate() {
            if part.is_empty()
                || !part.bytes().all(|c| c.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
            {
                bail!("invalid numeric version");
            }
            numbers[i] = part.parse()?;
        }
        let pre = pre.map(|p| p.split('.').collect::<Vec<_>>());
        if let Some(ids) = &pre {
            for id in ids {
                if id.is_empty()
                    || !id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                    || (id.bytes().all(|c| c.is_ascii_digit())
                        && id.len() > 1
                        && id.starts_with('0'))
                {
                    bail!("invalid prerelease version");
                }
            }
        }
        Ok((numbers, pre))
    }
    use std::cmp::Ordering;
    let (a, ap) = parts(candidate)?;
    let (b, bp) = parts(installed)?;
    let order = a.cmp(&b).then_with(|| match (ap, bp) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(a), Some(b)) => {
            for (x, y) in a.iter().zip(&b) {
                let xn = x.bytes().all(|c| c.is_ascii_digit());
                let yn = y.bytes().all(|c| c.is_ascii_digit());
                let cmp = match (xn, yn) {
                    (true, true) => x.len().cmp(&y.len()).then_with(|| x.cmp(y)),
                    (true, false) => Ordering::Less,
                    (false, true) => Ordering::Greater,
                    (false, false) => x.cmp(y),
                };
                if cmp != Ordering::Equal {
                    return cmp;
                }
            }
            a.len().cmp(&b.len())
        }
    });
    if order != Ordering::Greater {
        bail!("upgrade must be newer than the installed release");
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("release file exceeds size limit");
    }
    Ok(bytes)
}

pub fn verify(
    manifest: &Path,
    public_key: &str,
    platform: &str,
    architecture: &str,
    artifact: Option<&Path>,
) -> Result<Value> {
    if !matches!(platform, "linux" | "windows") || !matches!(architecture, "x86_64" | "arm64") {
        bail!("unsupported release platform/architecture");
    }
    let key: [u8; 32] = STANDARD
        .decode(public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("release public key must have 32 bytes"))?;
    let mut data: Value = serde_json::from_slice(&read_bounded(manifest, 1_048_576)?)?;
    let object = data.as_object_mut().context("manifest must be an object")?;
    let signature = object.remove("signature").context("missing signature")?;
    let signature = Signature::from_slice(
        &STANDARD.decode(signature.as_str().context("signature must be base64")?)?,
    )?;
    // serde_json's default map is ordered; this matches compact, sorted UTF-8
    // JSON used by the existing Python release signer. Release numbers must be
    // integers so cross-language float serialization cannot alter meaning.
    reject_floats(&data)?;
    VerifyingKey::from_bytes(&key)?
        .verify_strict(&serde_json::to_vec(&data)?, &signature)
        .context("manifest signature verification failed")?;
    if data["schema_version"].as_u64() != Some(1) || data["product"] != "commandcore-agent" {
        bail!("wrong release product/schema");
    }
    let version = data["version"].as_str().context("missing version")?;
    if version.is_empty()
        || version.len() > 61
        || !version.as_bytes()[0].is_ascii_alphanumeric()
        || !version
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    {
        bail!("invalid release version");
    }
    let matches: Vec<_> = data["artifacts"]
        .as_array()
        .context("missing artifacts")?
        .iter()
        .filter(|a| {
            a["platform"] == platform
                && a["architecture"] == architecture
                && a["kind"] == "executable"
        })
        .collect();
    if matches.len() != 1 {
        bail!("no unique supported executable");
    }
    let selected = matches[0];
    let url = Url::parse(selected["url"].as_str().context("missing artifact URL")?)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("artifact requires HTTPS without credentials/fragments");
    }
    let hash = selected["sha256"].as_str().context("missing hash")?;
    let size = selected["size"].as_u64().context("invalid artifact size")?;
    if !(1..=134_217_728).contains(&size)
        || hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("invalid artifact integrity metadata");
    }
    if let Some(path) = artifact {
        let bytes = read_bounded(path, size)?;
        if bytes.len() as u64 != size || hex::encode(Sha256::digest(&bytes)) != hash {
            bail!("artifact integrity verification failed");
        }
    }
    let mut metadata = selected.clone();
    metadata["version"] = json!(version);
    Ok(metadata)
}

fn reject_floats(value: &Value) -> Result<()> {
    match value {
        Value::Number(n) if n.is_f64() => bail!("floating point release metadata is unsupported"),
        Value::Object(m) => {
            for v in m.values() {
                reject_floats(v)?;
            }
        }
        Value::Array(a) => {
            for v in a {
                reject_floats(v)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::fs;

    #[test]
    fn upgrade_order_handles_prereleases_and_rejects_downgrades() {
        assert!(require_newer("1.0.0-rc.10", "1.0.0-rc.2").is_ok());
        assert!(require_newer("1.0.0", "1.0.0-rc.10").is_ok());
        assert!(require_newer("1.0.0-rc.2", "1.0.0-rc.10").is_err());
        assert!(require_newer("1.0.0", "1.0.0").is_err());
        assert!(require_newer("1.0.0-01", "0.9.0").is_err());
    }

    #[test]
    fn signed_artifact_and_tampering_gates() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = temp.path().join("manifest.json");
        let artifact = temp.path().join("agent.exe");
        let key = SigningKey::from_bytes(&[17; 32]);
        let public = STANDARD.encode(key.verifying_key().as_bytes());
        fs::write(&artifact, b"candidate").unwrap();
        let mut data = json!({"schema_version":1,"product":"commandcore-agent","version":"0.9.0-rc1","artifacts":[{"platform":"windows","architecture":"x86_64","kind":"executable","url":"https://example.invalid/agent.exe","size":9,"sha256":hex::encode(Sha256::digest(b"candidate"))}]});
        data["signature"] =
            json!(STANDARD.encode(key.sign(&serde_json::to_vec(&data).unwrap()).to_bytes()));
        fs::write(&manifest, serde_json::to_vec(&data).unwrap()).unwrap();
        assert!(verify(&manifest, &public, "windows", "x86_64", Some(&artifact)).is_ok());
        assert!(verify(&manifest, &public, "windows", "arm64", None).is_err());
        fs::write(&artifact, b"tampered!").unwrap();
        assert!(verify(&manifest, &public, "windows", "x86_64", Some(&artifact)).is_err());
        data["version"] = json!("1.0.0");
        fs::write(&manifest, serde_json::to_vec(&data).unwrap()).unwrap();
        assert!(verify(&manifest, &public, "windows", "x86_64", None).is_err());
    }
}
