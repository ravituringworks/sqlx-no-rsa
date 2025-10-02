use bytes::buf::Chain;
use bytes::Bytes;
use digest::{Digest, OutputSizeUser};
use generic_array::GenericArray;
// use rand::thread_rng;  // No longer needed without RSA
// use rsa::{pkcs8::DecodePublicKey, Oaep, RsaPublicKey};  // Removed to eliminate RSA vulnerability
use sha1::Sha1;
use sha2::Sha256;

use crate::connection::stream::MySqlStream;
use crate::error::Error;
use crate::protocol::auth::AuthPlugin;
use crate::protocol::Packet;

impl AuthPlugin {
    pub(super) async fn scramble(
        self,
        stream: &mut MySqlStream,
        password: &str,
        nonce: &Chain<Bytes, Bytes>,
    ) -> Result<Vec<u8>, Error> {
        match self {
            // https://mariadb.com/kb/en/caching_sha2_password-authentication-plugin/
            AuthPlugin::CachingSha2Password => Ok(scramble_sha256(password, nonce).to_vec()),

            AuthPlugin::MySqlNativePassword => Ok(scramble_sha1(password, nonce).to_vec()),

            // https://mariadb.com/kb/en/sha256_password-plugin/
            // RSA encryption removed due to security vulnerability (RUSTSEC-2023-0071)
            AuthPlugin::Sha256Password => encrypt_tls_only(stream, password).await,

            AuthPlugin::MySqlClearPassword => {
                let mut pw_bytes = password.as_bytes().to_owned();
                pw_bytes.push(0); // null terminate
                Ok(pw_bytes)
            }
        }
    }

    pub(super) async fn handle(
        self,
        stream: &mut MySqlStream,
        packet: Packet<Bytes>,
        password: &str,
        _nonce: &Chain<Bytes, Bytes>,  // Unused since RSA encryption was removed
    ) -> Result<bool, Error> {
        match self {
            AuthPlugin::CachingSha2Password if packet[0] == 0x01 => {
                match packet[1] {
                    // AUTH_OK
                    0x03 => Ok(true),

                    // AUTH_CONTINUE
                    0x04 => {
                        let payload = encrypt_tls_only(stream, password).await?;

                        stream.write_packet(&*payload)?;
                        stream.flush().await?;

                        Ok(false)
                    }

                    v => {
                        Err(err_protocol!("unexpected result from fast authentication 0x{:x} when expecting 0x03 (AUTH_OK) or 0x04 (AUTH_CONTINUE)", v))
                    }
                }
            }

            _ => Err(err_protocol!(
                "unexpected packet 0x{:02x} for auth plugin '{}' during authentication",
                packet[0],
                self.name()
            )),
        }
    }
}

fn scramble_sha1(
    password: &str,
    nonce: &Chain<Bytes, Bytes>,
) -> GenericArray<u8, <Sha1 as OutputSizeUser>::OutputSize> {
    // SHA1( password ) ^ SHA1( seed + SHA1( SHA1( password ) ) )
    // https://mariadb.com/kb/en/connection/#mysql_native_password-plugin

    let mut ctx = Sha1::new();

    ctx.update(password);

    let mut pw_hash = ctx.finalize_reset();

    ctx.update(pw_hash);

    let pw_hash_hash = ctx.finalize_reset();

    ctx.update(nonce.first_ref());
    ctx.update(nonce.last_ref());
    ctx.update(pw_hash_hash);

    let pw_seed_hash_hash = ctx.finalize();

    xor_eq(&mut pw_hash, &pw_seed_hash_hash);

    pw_hash
}

fn scramble_sha256(
    password: &str,
    nonce: &Chain<Bytes, Bytes>,
) -> GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize> {
    // XOR(SHA256(password), SHA256(seed, SHA256(SHA256(password))))
    // https://mariadb.com/kb/en/caching_sha2_password-authentication-plugin/#sha-2-encrypted-password
    let mut ctx = Sha256::new();

    ctx.update(password);

    let mut pw_hash = ctx.finalize_reset();

    ctx.update(pw_hash);

    let pw_hash_hash = ctx.finalize_reset();

    ctx.update(nonce.first_ref());
    ctx.update(nonce.last_ref());
    ctx.update(pw_hash_hash);

    let pw_seed_hash_hash = ctx.finalize();

    xor_eq(&mut pw_hash, &pw_seed_hash_hash);

    pw_hash
}

async fn encrypt_tls_only<'s>(
    stream: &'s mut MySqlStream,
    password: &'s str,
) -> Result<Vec<u8>, Error> {
    // TLS-only implementation to avoid RSA vulnerability (RUSTSEC-2023-0071)
    // https://mariadb.com/kb/en/caching_sha2_password-authentication-plugin/

    if stream.is_tls {
        // If in a TLS stream, send the password directly in clear text
        return Ok(to_asciz(password));
    }

    // For non-TLS connections, RSA encryption has been removed due to security concerns.
    // Return an error requiring TLS connection for secure authentication.
    Err(Error::protocol(
        "RSA password encryption has been disabled due to security vulnerability (RUSTSEC-2023-0071). \
         Please use TLS connections for Sha256Password or CachingSha2Password authentication. \
         Consider using MySqlNativePassword or enable TLS/SSL for your MySQL connection."
    ))
}

// XOR(x, y)
// If len(y) < len(x), wrap around inside y
fn xor_eq(x: &mut [u8], y: &[u8]) {
    let y_len = y.len();

    for i in 0..x.len() {
        x[i] ^= y[i % y_len];
    }
}

fn to_asciz(s: &str) -> Vec<u8> {
    let mut z = String::with_capacity(s.len() + 1);
    z.push_str(s);
    z.push('\0');

    z.into_bytes()
}

// RSA public key parsing function removed due to RSA vulnerability (RUSTSEC-2023-0071)
// fn parse_rsa_pub_key(key: &[u8]) -> Result<RsaPublicKey, Error> { ... }
