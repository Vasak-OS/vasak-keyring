//! Transport encryption for Secret Service sessions.
//!
//! The spec's `dh-ietf1024-sha256-aes128-cbc-pkcs7` algorithm, which is what
//! libsecret and the `secret-service` crate ask for. Every detail here is
//! load-bearing for interoperability — a peer that derives a different key just
//! sees corrupt secrets, with no error to point at the cause.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use num_bigint::BigUint;
use rand::RngCore;
use sha2::Sha256;

type Encryptor = cbc::Encryptor<aes::Aes128>;
type Decryptor = cbc::Decryptor<aes::Aes128>;

/// The algorithm name clients actually send. The short form
/// `dh-ietf1024-sha256` appears nowhere in the spec or in any client.
pub const DH_ALGORITHM: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";
pub const PLAIN_ALGORITHM: &str = "plain";

/// RFC 2409 §6.2 Second Oakley Group (1024-bit MODP), the group the spec names.
///
/// The previous constant was the first 128 bytes of RFC 3526's *1536-bit* group
/// truncated, which is not prime — so the modulus had unknown factorisation and
/// interoperated with nothing.
pub const DH_PRIME: [u8; 128] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

const DH_GENERATOR: u64 = 2;
/// Size of the modulus, and therefore of the shared secret once padded.
const DH_BYTES: usize = 128;
/// AES-128: the spec fixes this, regardless of the SHA-256 in the name.
const AES_KEY_BYTES: usize = 16;
const AES_BLOCK_BYTES: usize = 16;

/// A negotiated session key, plus the public value to hand back to the client.
pub struct DhSession {
    pub server_public: Vec<u8>,
    pub session_key: Vec<u8>,
}

/// Completes the DH exchange against a client's public value.
///
/// Rejects the degenerate values: 0, 1 and p-1 all yield a shared secret the
/// client can predict, which would let any caller fix the session key.
pub fn negotiate(client_public: &[u8]) -> Result<DhSession, String> {
    let prime = BigUint::from_bytes_be(&DH_PRIME);
    let client = BigUint::from_bytes_be(client_public);

    let one = BigUint::from(1u32);
    if client <= one || client >= &prime - &one {
        return Err("client public value is out of range".into());
    }

    let mut private_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut private_bytes);
    let private = BigUint::from_bytes_be(&private_bytes);

    let generator = BigUint::from(DH_GENERATOR);
    let server_public = generator.modpow(&private, &prime);
    let shared = client.modpow(&private, &prime);

    Ok(DhSession {
        server_public: pad_to_modulus(&server_public.to_bytes_be()),
        session_key: derive_key(&shared),
    })
}

/// Left-pads to the modulus size.
///
/// `to_bytes_be` drops leading zero bytes, and roughly one exchange in 256 has
/// one. The spec derives from the fixed-width secret, so without this the two
/// sides silently derive different keys that often — the kind of bug that looks
/// like flaky corruption rather than a protocol error.
fn pad_to_modulus(value: &[u8]) -> Vec<u8> {
    let mut padded = vec![0u8; DH_BYTES.saturating_sub(value.len())];
    padded.extend_from_slice(value);
    padded
}

/// HKDF-SHA256 with a null salt and empty info, truncated to the AES-128 key
/// size — not a bare SHA-256 of the secret, which is what this used to do.
fn derive_key(shared: &BigUint) -> Vec<u8> {
    let material = pad_to_modulus(&shared.to_bytes_be());
    let hkdf = hkdf::Hkdf::<Sha256>::new(None, &material);

    let mut key = vec![0u8; AES_KEY_BYTES];
    hkdf.expand(&[], &mut key)
        .expect("HKDF output length is valid for SHA-256");
    key
}

/// Encrypts a secret for transport. Returns `(iv, ciphertext)`; the IV travels
/// in the `parameters` field of the secret struct.
pub fn encrypt(session_key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let key = key_array(session_key)?;

    let mut iv = [0u8; AES_BLOCK_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut iv);

    let ciphertext = Encryptor::new(&key.into(), &iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    Ok((iv.to_vec(), ciphertext))
}

/// Decrypts a secret received from a client, using the IV it sent in
/// `parameters`.
pub fn decrypt(session_key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let key = key_array(session_key)?;

    if iv.len() != AES_BLOCK_BYTES {
        return Err(format!("expected a {AES_BLOCK_BYTES}-byte IV, got {}", iv.len()));
    }

    let mut iv_array = [0u8; AES_BLOCK_BYTES];
    iv_array.copy_from_slice(iv);

    Decryptor::new(&key.into(), &iv_array.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| "could not decrypt the secret".to_string())
}

fn key_array(session_key: &[u8]) -> Result<[u8; AES_KEY_BYTES], String> {
    if session_key.len() != AES_KEY_BYTES {
        return Err(format!(
            "session key is {} bytes, expected {AES_KEY_BYTES}",
            session_key.len()
        ));
    }

    let mut key = [0u8; AES_KEY_BYTES];
    key.copy_from_slice(session_key);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Miller-Rabin. The previous constant passed for a prime by inspection and
    /// was not one, so this is worth asserting rather than trusting the bytes.
    fn is_probable_prime(candidate: &BigUint, rounds: u32) -> bool {
        let one = BigUint::from(1u32);
        let two = BigUint::from(2u32);

        if *candidate <= one {
            return false;
        }

        let n_minus_one = candidate - &one;
        let mut d = n_minus_one.clone();
        let mut r = 0u32;
        while &d % &two == BigUint::from(0u32) {
            d /= &two;
            r += 1;
        }

        for base in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
            .into_iter()
            .take(rounds as usize)
        {
            let a = BigUint::from(base);
            let mut x = a.modpow(&d, candidate);

            if x == one || x == n_minus_one {
                continue;
            }

            let mut composite = true;
            for _ in 0..r - 1 {
                x = x.modpow(&two, candidate);
                if x == n_minus_one {
                    composite = false;
                    break;
                }
            }

            if composite {
                return false;
            }
        }

        true
    }

    #[test]
    fn the_modulus_is_a_1024_bit_safe_prime() {
        let prime = BigUint::from_bytes_be(&DH_PRIME);

        assert_eq!(prime.bits(), 1024, "the group must be 1024-bit");
        assert!(is_probable_prime(&prime, 12), "the modulus must be prime");

        let sophie_germain = (&prime - BigUint::from(1u32)) / BigUint::from(2u32);
        assert!(
            is_probable_prime(&sophie_germain, 12),
            "RFC 2409 group 2 is a safe prime"
        );
    }

    /// Both sides must land on the same key, including when the shared secret
    /// has leading zero bytes.
    #[test]
    fn both_peers_derive_the_same_key() {
        let prime = BigUint::from_bytes_be(&DH_PRIME);
        let generator = BigUint::from(DH_GENERATOR);

        let client_private = BigUint::from(0x0f0e_0d0c_0b0a_0908u64);
        let client_public = generator.modpow(&client_private, &prime);

        let session = negotiate(&client_public.to_bytes_be()).expect("negotiation");

        let server_public = BigUint::from_bytes_be(&session.server_public);
        let client_shared = server_public.modpow(&client_private, &prime);

        assert_eq!(session.session_key, derive_key(&client_shared));
        assert_eq!(session.session_key.len(), AES_KEY_BYTES);
    }

    #[test]
    fn the_server_public_value_is_always_modulus_sized() {
        let prime = BigUint::from_bytes_be(&DH_PRIME);
        let generator = BigUint::from(DH_GENERATOR);
        let client_public = generator.modpow(&BigUint::from(7u32), &prime);

        let session = negotiate(&client_public.to_bytes_be()).expect("negotiation");
        assert_eq!(session.server_public.len(), DH_BYTES);
    }

    /// A shared secret shorter than the modulus must still be padded before
    /// derivation, or the peers disagree about one exchange in 256.
    #[test]
    fn derivation_pads_a_short_shared_secret() {
        let short = BigUint::from(1u32);
        let padded_material = pad_to_modulus(&short.to_bytes_be());

        assert_eq!(padded_material.len(), DH_BYTES);
        assert_eq!(padded_material[DH_BYTES - 1], 1);
        assert!(padded_material[..DH_BYTES - 1].iter().all(|b| *b == 0));

        // Deriving from the unpadded bytes must give a different key, which is
        // exactly the bug this padding prevents.
        let unpadded = hkdf::Hkdf::<Sha256>::new(None, &short.to_bytes_be());
        let mut wrong = vec![0u8; AES_KEY_BYTES];
        unpadded.expand(&[], &mut wrong).unwrap();

        assert_ne!(derive_key(&short), wrong);
    }

    #[test]
    fn degenerate_client_values_are_rejected() {
        let prime = BigUint::from_bytes_be(&DH_PRIME);

        for bad in [
            BigUint::from(0u32),
            BigUint::from(1u32),
            &prime - BigUint::from(1u32),
            prime.clone(),
        ] {
            assert!(
                negotiate(&bad.to_bytes_be()).is_err(),
                "should reject {bad}"
            );
        }
    }

    #[test]
    fn transport_round_trips() {
        let key = vec![0x24u8; AES_KEY_BYTES];
        let secret = b"correct horse battery staple";

        let (iv, ciphertext) = encrypt(&key, secret).expect("encrypt");

        assert_eq!(iv.len(), AES_BLOCK_BYTES);
        assert_ne!(&ciphertext[..], &secret[..], "must not be plaintext");
        assert_eq!(ciphertext.len() % AES_BLOCK_BYTES, 0, "PKCS7-padded");

        assert_eq!(decrypt(&key, &iv, &ciphertext).expect("decrypt"), secret);
    }

    #[test]
    fn an_empty_secret_survives_the_round_trip() {
        let key = vec![0x11u8; AES_KEY_BYTES];
        let (iv, ciphertext) = encrypt(&key, b"").expect("encrypt");

        assert_eq!(ciphertext.len(), AES_BLOCK_BYTES, "a full block of padding");
        assert_eq!(decrypt(&key, &iv, &ciphertext).expect("decrypt"), b"");
    }

    #[test]
    fn the_wrong_key_or_iv_does_not_return_the_secret() {
        let key = vec![0x24u8; AES_KEY_BYTES];
        let (iv, ciphertext) = encrypt(&key, b"top secret").expect("encrypt");

        let other_key = vec![0x25u8; AES_KEY_BYTES];
        if let Ok(plaintext) = decrypt(&other_key, &iv, &ciphertext) {
            assert_ne!(plaintext, b"top secret");
        }

        let mut other_iv = iv.clone();
        other_iv[0] ^= 0xff;
        if let Ok(plaintext) = decrypt(&key, &other_iv, &ciphertext) {
            assert_ne!(plaintext, b"top secret");
        }
    }

    #[test]
    fn a_mis_sized_key_or_iv_is_rejected() {
        assert!(encrypt(&[0u8; 32], b"x").is_err(), "AES-256 key must be rejected");
        assert!(decrypt(&[0u8; AES_KEY_BYTES], &[0u8; 12], &[0u8; 16]).is_err(), "GCM-sized IV");
    }
}
