mod chain;
#[macro_use]
mod consts;
use blake3::Hash;
use chain::Chain;
use chrono::{DateTime, Utc};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::signature::Verifier;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use rsa::{
    pss::{BlindedSigningKey, Signature, VerifyingKey},
    sha2::Sha256,
    Pss, RsaPrivateKey, RsaPublicKey,
};
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize,
};
use std::fmt::Debug;
use std::{any::Any, fmt};
use validator::Validate;

/// The `CertificatePermission` enum represents the type of certificate in the chain of trust.
/// A `Root` certificate has no parent and can have children.
/// A `Delegate` certificate has a parent and can have children.
/// A `Verify` The certificate has a parent but can't have children.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificatePermission {
    /// Accepts the certificate as root authority, meaning that it doesn't require signature to be valid (blind trust)
    Root = 2,
    /// Accepts certificate as sub-authority, meaning that those certs are able to sign other certs
    Delegate = 1,
    /// Accept certificate as sign-only one, meaning that those certificates can only sign messages, and not other certificates
    Verify = 0,
}
impl CertificatePermission {
    pub fn is_valid_to_sign<T>(
        self_signed: &Signed<T>,
        requested_perm: CertificatePermission,
    ) -> Result<(), error::SignError> {
        use error::SignError::*;
        use CertificatePermission::*;
        match self_signed {
            Signed::Cerf { inner, permission } => match permission {
                Root | Delegate => match requested_perm {
                    Root => Err(PermissionDenied {
                        received: requested_perm,
                        expected: vec![Delegate, Verify],
                    }),
                    Delegate => Ok(()),
                    Verify => Ok(()),
                },
                Verify => Err(PermissionDenied {
                    received: requested_perm,
                    expected: vec![],
                }),
            },
            Signed::Data { inner, data } => Err(PermissionDenied {
                received: requested_perm,
                expected: vec![],
            }),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Signer {
    pub_key: RsaPublicKey,
    signature: Box<[u8]>,
}
impl Signer {
    pub fn signature(&self) -> Signature {
        rsa::pss::Signature::try_from(self.signature.as_ref()).unwrap()
    }
}
impl Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer")
            .field(
                "pub_key",
                &self
                    .pub_key
                    .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
                    .unwrap(),
            )
            .field(
                "signature",
                &base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    self.signature.clone(),
                ),
            )
            .finish()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ValidTimeRange {
    start: chrono::DateTime<Utc>,
    end: chrono::DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
struct SignedInner {
    holder_public_key: RsaPublicKey,
    holder_signers_chain: crate::chain::Chain,
    claims: Vec<String>,
    valid_time_range: ValidTimeRange,
}
impl Debug for SignedInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedInner")
            .field(
                "holder_public_key",
                &self
                    .holder_public_key
                    .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
                    .unwrap(),
            )
            .field("holder_signers_chain", &self.holder_signers_chain)
            .field("claims", &self.claims)
            .field("valid_time_range", &self.valid_time_range)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Signed<T> {
    Cerf {
        inner: SignedInner,
        permission: CertificatePermission,
    },
    Data {
        inner: SignedInner,
        data: T,
    },
}
impl<T> Signed<T> {
    pub fn inner(&self) -> &SignedInner {
        match self {
            Signed::Cerf { inner, permission } => inner,
            Signed::Data { inner, data } => inner,
        }
    }
}
impl<'de, T: Serialize + Deserialize<'de>> Signed<T> {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
    pub fn from_bytes(bytes: &'de [u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
    pub fn sign(&self, private_key: &RsaPrivateKey) -> Signer {
        let data = self.to_bytes();
        let signer = BlindedSigningKey::<Sha256>::new(private_key.clone());
        let signature = signer
            .sign_with_rng(&mut rand::thread_rng(), data.as_ref())
            .to_bytes();
        Signer {
            pub_key: private_key.to_public_key(),
            signature,
        }
    }
}
impl<T: Debug> Debug for Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Signed::Cerf { inner, permission } => f
                .debug_struct("Signed::Cerf")
                .field("inner", inner)
                .field("permission", permission)
                .finish(),
            Signed::Data { inner, data } => f
                .debug_struct("Signed::Data")
                .field("inner", inner)
                .field("data", data)
                .finish(),
        }
    }
}

// mod lolkekcheburek {
//     use rsa::RsaPublicKey;
//     use serde::{Deserialize, Serialize};

//     #[derive(Deserialize, Serialize)]
//     pub struct SignatureInner<T> {
//         data: T,
//         valid_until: chrono::DateTime<chrono::Utc>,
//         claims: Vec<String>,
//     }

//     #[derive(Deserialize, Serialize)]
//     pub struct Signature<T> {
//         info: SignatureInner<T>,
//         proof: (),
//         signer: RsaPublicKey,
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DataSignature<T> {
    // Proof that the owner has signed the `cerf` field
    signer: Signer,
    // data part
    signed: Signed<T>,
}
impl<'de, T: Serialize + Deserialize<'de>> DataSignature<T> {
    pub fn new_signed(cerf: Signed<T>, private_key: &RsaPrivateKey) -> Self {
        match cerf {
            Signed::Cerf { inner, permission } => {
                let cerf = Signed::Cerf { inner, permission };
                let signer = cerf.sign(private_key);
                DataSignature {
                    signer,
                    signed: cerf,
                }
            }
            Signed::Data { inner, data } => {
                let cerf = Signed::Data { inner, data };
                let signer = cerf.sign(private_key);
                DataSignature {
                    signer,
                    signed: cerf,
                }
            }
        }
    }
}

mod error {
    use chrono::{DateTime, Utc};
    use thiserror::Error;

    use crate::CertificatePermission;

    #[derive(Error, Debug, PartialEq, Eq)]
    pub enum SignError {
        #[error(transparent)]
        TimeRangeError(#[from] TimeRangeError),
        #[error(transparent)]
        CryptographyError(#[from] CryptographyError),
        #[error(
            "Permission denied, received: {received:?}, but expected one of this: {expected:?}"
        )]
        PermissionDenied {
            received: CertificatePermission,
            expected: Vec<CertificatePermission>,
        },
    }

    #[derive(Error, Debug, PartialEq, Eq)]
    pub enum CryptographyError {
        #[error("Invalid private key")]
        InvalidPrivateKey,
    }

    #[derive(Error, Debug, PartialEq, Eq)]
    pub enum TimeRangeError {
        #[error("Invalid start time, received: {received} but not expected before: {expected}")]
        InvalidStart {
            received: DateTime<Utc>,
            expected: DateTime<Utc>,
        },
        #[error("Invalid end time, received: {received}, but not expected after: {expected}")]
        InvalidEnd {
            received: DateTime<Utc>,
            expected: DateTime<Utc>,
        },
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PublicSignedData<T> {
    public_key: RsaPublicKey,
    data_signature: DataSignature<T>,
}
impl<'de, T: Serialize + Deserialize<'de>> PublicSignedData<T> {
    pub fn verify(&self) -> Result<(), &'static str> {
        let data = self.data_signature.signed.to_bytes();
        let signature = self.data_signature.signer.signature();
        let verifying_key = VerifyingKey::<Sha256>::new(self.public_key.clone());
        verifying_key
            .verify(data.as_ref(), &signature)
            .map_err(|_| "failed to verify")?;
        Ok(())
    }
}
impl<T: Debug> Debug for PublicSignedData<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PubCertificate")
            .field(
                "public_key",
                &self
                    .public_key
                    .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
                    .unwrap(),
            )
            .field("data_signature", &self.data_signature)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct OwnedSignedData<T> {
    private_key: rsa::RsaPrivateKey,
    data_signature: DataSignature<T>,
}
impl<'de, T: Serialize + Deserialize<'de> + Clone> OwnedSignedData<T> {
    pub fn from_pub_certificate(
        cert_private_key: RsaPrivateKey,
        cert: PublicSignedData<T>,
    ) -> Result<Self, error::CryptographyError> {
        if cert_private_key.to_public_key() != cert.public_key {
            return Err(error::CryptographyError::InvalidPrivateKey);
        }
        Ok(OwnedSignedData {
            private_key: cert_private_key,
            data_signature: cert.data_signature,
        })
    }
    pub fn sign_cerf(
        &self,
        pub_key: RsaPublicKey,
        claims: Vec<String>,
        permission: CertificatePermission,
        valid_time_range: Option<ValidTimeRange>,
    ) -> Result<PublicSignedData<T>, error::SignError> {
        CertificatePermission::is_valid_to_sign(&self.data_signature.signed, permission)?;
        let valid_time_range = Self::check_und_unwrap_time_range(
            valid_time_range,
            self.data_signature.signed.inner().valid_time_range.clone(),
        )?;
        let cerf = Signed::Cerf {
            inner: SignedInner {
                holder_public_key: pub_key.clone(),
                holder_signers_chain: self
                    .data_signature
                    .signed
                    .inner()
                    .holder_signers_chain
                    .expand(self.private_key.to_public_key(), permission),
                claims,
                valid_time_range,
            },
            permission,
        };
        Ok(PublicSignedData {
            public_key: pub_key,
            data_signature: DataSignature::new_signed(cerf, &self.private_key),
        })
    }
    fn check_und_unwrap_time_range(
        new_time_range: Option<ValidTimeRange>,
        self_time_range: ValidTimeRange,
    ) -> Result<ValidTimeRange, error::TimeRangeError> {
        if let Some(time_range) = new_time_range {
            if time_range.start > self_time_range.start {
                return Err(error::TimeRangeError::InvalidStart {
                    received: time_range.start,
                    expected: self_time_range.start,
                });
            }
            if time_range.end < self_time_range.end {
                return Err(error::TimeRangeError::InvalidEnd {
                    received: time_range.end,
                    expected: self_time_range.end,
                });
            }
            Ok(time_range)
        } else {
            Ok(ValidTimeRange {
                start: self_time_range.start,
                end: self_time_range.end,
            })
        }
    }
}
impl OwnedSignedData<()> {
    pub fn new_root(claims: Vec<String>, valid_time_range: Option<ValidTimeRange>) -> Self {
        let private_key =
            RsaPrivateKey::new(&mut rand::thread_rng(), consts::PrivKey::BITS).unwrap();
        let cerf = Signed::Cerf {
            inner: SignedInner {
                holder_public_key: private_key.to_public_key(),
                holder_signers_chain: Chain::new(),
                claims,
                valid_time_range: valid_time_range.unwrap_or(ValidTimeRange {
                    start: DateTime::<Utc>::MIN_UTC,
                    end: DateTime::<Utc>::MAX_UTC,
                }),
            },
            permission: CertificatePermission::Root,
        };
        OwnedSignedData {
            private_key: private_key.clone(),
            data_signature: DataSignature::new_signed(cerf, &private_key),
        }
    }
}
impl<T: Clone> OwnedSignedData<T> {
    pub fn get_pub(&self) -> PublicSignedData<T> {
        PublicSignedData {
            public_key: self.private_key.to_public_key(),
            data_signature: self.data_signature.clone(),
        }
    }
}
impl<T: Debug> Debug for OwnedSignedData<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedSignedData")
            .field(
                "private_key",
                &self
                    .private_key
                    .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
                    .unwrap(),
            )
            .field("data_signature", &self.data_signature)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SignedData<T> {
    Pub(PublicSignedData<T>),
    Owned(OwnedSignedData<T>),
}
impl<T: Clone> SignedData<T> {
    pub fn as_pub(&self) -> PublicSignedData<T> {
        match self {
            SignedData::Pub(cert) => cert.clone(),
            SignedData::Owned(cert) => cert.get_pub(),
        }
    }
}

#[cfg(test)]
mod tests {
    use rsa::RsaPrivateKey;
    use tokio::sync::mpsc::{
        error::SendError, unbounded_channel, UnboundedReceiver, UnboundedSender,
    };

    use crate::{consts, CertificatePermission, OwnedSignedData, ValidTimeRange};

    struct DuplexChannel<T, Y> {
        tx: UnboundedSender<T>,
        rx: UnboundedReceiver<Y>,
    }
    impl<T, Y> DuplexChannel<T, Y> {
        pub fn new() -> (DuplexChannel<T, Y>, DuplexChannel<Y, T>) {
            let (tx1, rx1) = unbounded_channel();
            let (tx2, rx2) = unbounded_channel();
            (
                DuplexChannel { tx: tx2, rx: rx1 },
                DuplexChannel { tx: tx1, rx: rx2 },
            )
        }
        pub fn send(&mut self, msg: T) -> Result<(), SendError<T>> {
            self.tx.send(msg)
        }
        pub async fn recv(&mut self) -> Option<Y> {
            self.rx.recv().await
        }
    }

    #[tokio::test]
    async fn test_sign_and_verify() {
        // channels setup
        let (mut root, mut root_backend) = DuplexChannel::new();
        let (mut root2, mut root_backend2) = DuplexChannel::new();
        let (mut delegate, mut delegate_backend) = DuplexChannel::new();
        let (mut delegate2, mut delegate_backend2) = DuplexChannel::new();
        let (mut verify, mut verify_backend) = DuplexChannel::new();

        type Request = (
            &'static str,
            rsa::RsaPublicKey,
            Vec<String>,
            CertificatePermission,
            Option<ValidTimeRange>,
        );

        // root1 - remote certificate
        tokio::spawn(async move {
            let root_cert = OwnedSignedData::new_root(vec![], None);

            loop {
                tokio::select! {
                    Some(request) = root_backend.recv() => {
                        let request: Request = request;
                        let x = root_cert.sign_cerf(request.1, request.2, request.3, request.4);
                        root_backend.send(x).unwrap();
                    }
                    Some(request) = root_backend2.recv() => {
                        let request: Request = request;
                        let x = root_cert.sign_cerf(request.1, request.2, request.3, request.4);
                        root_backend2.send(x).unwrap();
                    }
                    else => {}
                }
            }
        });

        // delegate1 - remote certificate
        tokio::spawn(async move {
            let private_key =
                RsaPrivateKey::new(&mut rand::thread_rng(), consts::PrivKey::BITS).unwrap();
            let request: Request = (
                "gime pls delegate ceft",
                private_key.to_public_key(),
                vec![],
                CertificatePermission::Delegate,
                None,
            );
            root2.send(request).unwrap();
            let delegate_cerf_pub = root2.recv().await.unwrap().unwrap();
            let delegate_cert =
                OwnedSignedData::from_pub_certificate(private_key.clone(), delegate_cerf_pub)
                    .unwrap();
            assert_eq!(
                private_key.to_public_key(),
                delegate_cert
                    .data_signature
                    .signed
                    .inner()
                    .holder_public_key
            );

            loop {
                tokio::select! {
                    Some(request) = delegate_backend.recv() => {
                        let request: Request = request;
                        let x = delegate_cert.sign_cerf(request.1, request.2, request.3, request.4);
                        delegate_backend.send(x).unwrap();
                    }
                    Some(request) = delegate_backend2.recv() => {
                        let request: Request = request;
                        let x = delegate_cert.sign_cerf(request.1, request.2, request.3, request.4);
                        delegate_backend2.send(x).unwrap();
                    }
                    else => {}
                }
            }
        });

        // verify1 - remote certificate
        tokio::spawn(async move {
            let private_key =
                RsaPrivateKey::new(&mut rand::thread_rng(), consts::PrivKey::BITS).unwrap();
            let request: Request = (
                "gime pls verify ceft",
                private_key.to_public_key(),
                vec![],
                CertificatePermission::Delegate,
                None,
            );
            delegate2.send(request).unwrap();
            let pub_verify_cerf = delegate2.recv().await.unwrap().unwrap();
            let verify_cerf =
                OwnedSignedData::from_pub_certificate(private_key.clone(), pub_verify_cerf)
                    .unwrap();
            assert_eq!(
                private_key.to_public_key(),
                verify_cerf.data_signature.signed.inner().holder_public_key
            );

            loop {
                tokio::select! {
                    Some(request) = verify_backend.recv() => {
                        let request: Request = request;
                        let x = verify_cerf.sign_cerf(request.1, request.2, request.3, request.4);
                        verify_backend.send(x).unwrap();
                    }
                    else => {}
                }
            }
        });

        {
            // Getting `Delegate2` certificate from `Root1`
            let root_delegate2_pk =
                RsaPrivateKey::new(&mut rand::thread_rng(), consts::PrivKey::BITS).unwrap();
            let root_delegate2 =
                OwnedSignedData::from_pub_certificate(root_delegate2_pk.clone(), {
                    root.send((
                        "gime pls delegate ceft",
                        root_delegate2_pk.to_public_key(),
                        vec![],
                        CertificatePermission::Delegate,
                        None,
                    ))
                    .unwrap();
                    root.recv().await.unwrap().unwrap()
                })
                .unwrap();
            assert_eq!(
                root_delegate2_pk.to_public_key(),
                root_delegate2
                    .data_signature
                    .signed
                    .inner()
                    .holder_public_key
            );

            // Getting `Verify1` certificate from `Delegate2`
            let root_delegate2_verify_pk =
                RsaPrivateKey::new(&mut rand::thread_rng(), consts::PrivKey::BITS).unwrap();
            let root_delegate2_verify = OwnedSignedData::from_pub_certificate(
                root_delegate2_verify_pk.clone(),
                root_delegate2
                    .sign_cerf(
                        root_delegate2_verify_pk.to_public_key(),
                        vec!["Life for Aiur".to_string()],
                        CertificatePermission::Verify,
                        None,
                    )
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                root_delegate2_verify_pk.to_public_key(),
                root_delegate2_verify
                    .data_signature
                    .signed
                    .inner()
                    .holder_public_key
            );

            // Trying to get `Verify2` certificate from `Verify1`
            let root_delegate2_verify_verify_pk =
                RsaPrivateKey::new(&mut rand::thread_rng(), consts::PrivKey::BITS).unwrap();
            let root_delegate2_verify_verify_result = root_delegate2_verify.sign_cerf(
                root_delegate2_verify_verify_pk.to_public_key(),
                vec!["Life for Amon".to_string()],
                CertificatePermission::Verify,
                None,
            );
            assert_eq!(
                root_delegate2_verify_verify_result,
                Err(crate::error::SignError::PermissionDenied {
                    received: CertificatePermission::Verify,
                    expected: vec![]
                })
            );

            // Trying to get `Root2` certificate from `Root1`
            let root_root2_pk =
                RsaPrivateKey::new(&mut rand::thread_rng(), consts::PrivKey::BITS).unwrap();
            root.send((
                "gime pls delegate ceft",
                root_root2_pk.to_public_key(),
                vec![],
                CertificatePermission::Root,
                None,
            ))
            .unwrap();
            let root_root2_result = root.recv().await.unwrap();
            assert_eq!(
                root_root2_result,
                Err(crate::error::SignError::PermissionDenied {
                    received: CertificatePermission::Root,
                    expected: vec![
                        CertificatePermission::Delegate,
                        CertificatePermission::Verify
                    ]
                })
            );

            // Trying to get `Root2` certificate from `Delegate1`
            let delegate_root2_pk =
                RsaPrivateKey::new(&mut rand::thread_rng(), consts::PrivKey::BITS).unwrap();
            delegate
                .send((
                    "gime pls delegate ceft",
                    delegate_root2_pk.to_public_key(),
                    vec![],
                    CertificatePermission::Root,
                    None,
                ))
                .unwrap();
            let delegate_root2_result = delegate.recv().await.unwrap();
            assert_eq!(
                delegate_root2_result,
                Err(crate::error::SignError::PermissionDenied {
                    received: CertificatePermission::Root,
                    expected: vec![
                        CertificatePermission::Delegate,
                        CertificatePermission::Verify
                    ]
                })
            );

            dbg!(root_delegate2_verify);
        }

        // Root -> `Verify2`
    }
}
