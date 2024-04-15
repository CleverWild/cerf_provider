use std::fmt::{self, Display, Formatter};

use rsa::{pkcs1::EncodeRsaPublicKey, traits::PublicKeyParts, RsaPublicKey};
use serde::{Deserialize, Serialize};

use crate::CertificatePermission;

impl Display for CertificatePermission {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            CertificatePermission::Root => write!(f, "Root"),
            CertificatePermission::Delegate => write!(f, "Delegate"),
            CertificatePermission::Verify => write!(f, "Verify-only"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
struct CerfInfo {
    pub cerf_type: CertificatePermission,
    pub pub_key: RsaPublicKey,
}
impl Display for CerfInfo {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{} cerf with public key: `{}`",
            self.cerf_type,
            self.pub_key.n()
        )
    }
}
impl std::fmt::Debug for CerfInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CerfInfo")
            .field("cerf_type", &self.cerf_type)
            .field("pub_key", &self.pub_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap())
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Chain(Vec<CerfInfo>);
impl Chain {
    pub fn new() -> Self {
        Chain(Vec::new())
    }

    pub fn expand(&self, pub_key: RsaPublicKey, cerf_type: CertificatePermission) -> Self {
        let mut new_inner = self.0.clone();
        new_inner.push(CerfInfo { pub_key, cerf_type });
        Chain(new_inner)
    }
}
impl Display for Chain {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut iter = self.0.iter().peekable();
        if iter.len() == 0 {
            return write!(f, "Empty chain");
        }

        if iter.peek().unwrap().cerf_type != CertificatePermission::Root {
            tracing::error!(name: "chain", "First cerf is not root");
        }

        writeln!(f, "R: {}", iter.next().unwrap())?;
        for cerf_info in iter {
            writeln!(f, "-> {}", cerf_info)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rsa::RsaPrivateKey;

    use crate::consts;

    use super::*;

    #[test]
    fn test_chain() {
        println!("{}", Chain::new());
        let chain = Chain::new()
            .expand(
                RsaPrivateKey::new(&mut rand::thread_rng(), consts::PrivKey::BYTES)
                    .unwrap()
                    .to_public_key(),
                CertificatePermission::Root,
            )
            .expand(
                RsaPrivateKey::new(&mut rand::thread_rng(), consts::PrivKey::BYTES)
                    .unwrap()
                    .to_public_key(),
                CertificatePermission::Delegate,
            )
            .expand(
                RsaPrivateKey::new(&mut rand::thread_rng(), consts::PrivKey::BYTES)
                    .unwrap()
                    .to_public_key(),
                CertificatePermission::Verify,
            );

        println!("{}", chain);
        // assert_eq!(
        //     chain.to_string(),
        //     "R: Root cerf with public key: 1\n-> Intermediate cerf with public key: 3\n-> EndEntity cerf with public key: 5\n"
        // );
    }
}
