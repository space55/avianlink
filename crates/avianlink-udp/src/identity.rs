//! The identity file: the 32-byte secret seed, owner-readable only. It is
//! kept apart from `Storage` (`docs/security.md` §2).

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use avianlink_core::{Identity, PublicKey};

use crate::os_rng;

/// Loads the identity in `dir`, if there is one.
pub fn load_identity(dir: &Path) -> io::Result<Option<Identity>> {
    match fs::read(dir.join("identity")) {
        Ok(bytes) => {
            let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "identity file must be 32 bytes")
            })?;
            Ok(Some(Identity::from_secret_bytes(&seed)))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Writes a new identity to `dir` (mode 0600). Fails if one exists.
pub(crate) fn create_identity(dir: &Path) -> io::Result<Identity> {
    fs::create_dir_all(dir)?;
    let id = Identity::generate(&mut os_rng());
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join("identity"))?;
    f.write_all(id.secret_bytes().as_ref())?;
    f.sync_all()?;
    Ok(id)
}

/// Lowercase hex of a public key (the address format of the CLI).
pub fn public_key_hex(key: &PublicKey) -> String {
    key.0.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses 64 hex characters into a public key.
pub fn parse_public_key(s: &str) -> Option<PublicKey> {
    if s.len() != 64 {
        return None;
    }
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(PublicKey(k))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_file_round_trips_and_is_private() {
        let d = std::env::temp_dir().join(format!("avianlink-id-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        assert!(load_identity(&d).unwrap().is_none());
        let a = create_identity(&d).unwrap();
        assert!(create_identity(&d).is_err(), "never replaced");
        let b = load_identity(&d).unwrap().unwrap();
        assert_eq!(a.public_key(), b.public_key());
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(d.join("identity"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let hex = public_key_hex(&a.public_key());
        assert_eq!(parse_public_key(&hex), Some(a.public_key()));
        assert_eq!(parse_public_key("zz"), None);
        let _ = fs::remove_dir_all(&d);
    }
}
