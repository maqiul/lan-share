//! LSP v3.0 加密模块
//!
//! 使用 X25519 密钥交换 + ChaCha20-Poly1305 AEAD 加密
//! 密钥派生使用 HKDF-SHA256

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// X25519 密钥对
pub struct KeyPair {
    secret: StaticSecret,
    pub public_key: [u8; 32],
}

impl KeyPair {
    /// 生成新的密钥对
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        Self {
            public_key: public.to_bytes(),
            secret,
        }
    }

    /// 计算共享密钥（X25519 ECDH）
    ///
    /// 双方使用各自的私钥和对方的公钥，计算出相同的共享密钥。
    pub fn compute_shared_secret(&self, peer_public_key: &[u8; 32]) -> [u8; 32] {
        let peer_public = PublicKey::from(*peer_public_key);
        let shared = self.secret.diffie_hellman(&peer_public);
        *shared.as_bytes()
    }
}

/// HKDF-SHA256 密钥派生
pub fn hkdf_sha256(
    ikm: &[u8],    // 输入密钥材料
    salt: &[u8],   // 盐
    info: &[u8],   // 上下文信息
    length: usize, // 输出长度
) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .expect("HKDF expand failed");
    okm
}

/// 会话密钥
#[derive(Clone)]
pub struct SessionKeys {
    /// 客户端→服务端 加密密钥
    pub client_write_key: [u8; 32],
    /// 服务端→客户端 加密密钥
    pub server_write_key: [u8; 32],
    /// 客户端→服务端 IV 基础值（实际 nonce = base ^ counter）
    pub client_write_iv: [u8; 12],
    /// 服务端→客户端 IV 基础值
    pub server_write_iv: [u8; 12],
}

impl SessionKeys {
    /// 从共享密钥派生会话密钥
    pub fn derive(shared_secret: &[u8; 32], handshake_hash: &[u8]) -> Self {
        // 派生主密钥
        let master_key = hkdf_sha256(shared_secret, b"lsp-master-key", handshake_hash, 32);

        // 派生各方向密钥和 IV
        let client_key = hkdf_sha256(&master_key, b"", b"lsp-client-write-key", 32);
        let server_key = hkdf_sha256(&master_key, b"", b"lsp-server-write-key", 32);
        let client_iv = hkdf_sha256(&master_key, b"", b"lsp-client-write-iv", 12);
        let server_iv = hkdf_sha256(&master_key, b"", b"lsp-server-write-iv", 12);

        let mut client_write_key = [0u8; 32];
        let mut server_write_key = [0u8; 32];
        let mut client_write_iv = [0u8; 12];
        let mut server_write_iv = [0u8; 12];

        client_write_key.copy_from_slice(&client_key);
        server_write_key.copy_from_slice(&server_key);
        client_write_iv.copy_from_slice(&client_iv);
        server_write_iv.copy_from_slice(&server_iv);

        Self {
            client_write_key,
            server_write_key,
            client_write_iv,
            server_write_iv,
        }
    }
}

/// ChaCha20-Poly1305 AEAD 加密/解密
pub mod aead {
    use super::*;

    /// 加密
    ///
    /// 返回 (ciphertext_with_tag, nonce)
    /// ciphertext_with_tag = ciphertext || 16-byte tag（chacha20poly1305 crate 的格式）
    pub fn encrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> (Vec<u8>, [u8; 16]) {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let nonce = Nonce::from_slice(nonce);

        let ciphertext_with_tag = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("ChaCha20-Poly1305 encryption failed");

        // chacha20poly1305 crate 输出格式：ciphertext || tag(16B)
        let tag_start = ciphertext_with_tag.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ciphertext_with_tag[tag_start..]);

        // 返回纯密文（不含 tag）和 tag 分开
        let ciphertext = ciphertext_with_tag[..tag_start].to_vec();

        (ciphertext, tag)
    }

    /// 解密
    pub fn decrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, &'static str> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let nonce = Nonce::from_slice(nonce);

        // 重组 ciphertext || tag
        let mut ciphertext_with_tag = Vec::with_capacity(ciphertext.len() + 16);
        ciphertext_with_tag.extend_from_slice(ciphertext);
        ciphertext_with_tag.extend_from_slice(tag);

        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext_with_tag,
                    aad,
                },
            )
            .map_err(|_| "Authentication failed")
    }

    /// 生成随机 nonce
    pub fn generate_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    #[test]
    fn test_key_exchange_produces_same_secret() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let alice_shared = alice.compute_shared_secret(&bob.public_key);
        let bob_shared = bob.compute_shared_secret(&alice.public_key);

        // X25519 保证双方计算出相同的共享密钥
        assert_eq!(alice_shared, bob_shared, "X25519 shared secrets must match");
    }

    #[test]
    fn test_different_keys_produce_different_secrets() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let eve = KeyPair::generate();

        let ab = alice.compute_shared_secret(&bob.public_key);
        let ae = alice.compute_shared_secret(&eve.public_key);

        assert_ne!(ab, ae, "Different peers must produce different secrets");
    }

    #[test]
    fn test_session_keys_derive() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let shared = alice.compute_shared_secret(&bob.public_key);
        let handshake_hash = [0xABu8; 32];

        let keys_a = SessionKeys::derive(&shared, &handshake_hash);
        let keys_b = SessionKeys::derive(&shared, &handshake_hash);

        // 相同输入必须产生相同密钥
        assert_eq!(keys_a.client_write_key, keys_b.client_write_key);
        assert_eq!(keys_a.server_write_key, keys_b.server_write_key);
        assert_eq!(keys_a.client_write_iv, keys_b.client_write_iv);
        assert_eq!(keys_a.server_write_iv, keys_b.server_write_iv);

        // 不同方向的密钥必须不同
        assert_ne!(keys_a.client_write_key, keys_a.server_write_key);
    }

    #[test]
    fn test_aead_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = aead::generate_nonce();
        let aad = b"header data";
        let plaintext = b"Hello, LSP v3.0!";

        let (ciphertext, tag) = aead::encrypt(&key, &nonce, aad, plaintext);
        let decrypted = aead::decrypt(&key, &nonce, aad, &ciphertext, &tag).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_aead_tamper_detection() {
        let key = [0x42u8; 32];
        let nonce = aead::generate_nonce();
        let aad = b"header data";
        let plaintext = b"Hello, LSP!";

        let (mut ciphertext, tag) = aead::encrypt(&key, &nonce, aad, plaintext);

        // 篡改密文
        ciphertext[0] ^= 0xFF;

        // 解密应该失败
        assert!(aead::decrypt(&key, &nonce, aad, &ciphertext, &tag).is_err());
    }

    #[test]
    fn test_aead_wrong_key() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let nonce = aead::generate_nonce();
        let aad = b"";
        let plaintext = b"secret";

        let (ciphertext, tag) = aead::encrypt(&key1, &nonce, aad, plaintext);

        // 用错误的密钥解密应该失败
        assert!(aead::decrypt(&key2, &nonce, aad, &ciphertext, &tag).is_err());
    }

    #[test]
    fn test_aead_wrong_aad() {
        let key = [0x42u8; 32];
        let nonce = aead::generate_nonce();
        let plaintext = b"secret";

        let (ciphertext, tag) = aead::encrypt(&key, &nonce, b"correct aad", plaintext);

        // 用错误的 AAD 解密应该失败
        assert!(aead::decrypt(&key, &nonce, b"wrong aad", &ciphertext, &tag).is_err());
    }

    #[test]
    fn test_full_handshake_and_encrypt() {
        // 模拟完整的密钥交换 + 加密通信
        let client = KeyPair::generate();
        let server = KeyPair::generate();

        // 双方计算共享密钥
        let client_shared = client.compute_shared_secret(&server.public_key);
        let server_shared = server.compute_shared_secret(&client.public_key);
        assert_eq!(client_shared, server_shared);

        // 计算握手哈希
        let handshake_hash = sha2::Digest::finalize(
            sha2::Sha256::new()
                .chain_update(&client.public_key)
                .chain_update(&server.public_key),
        );
        let mut hh = [0u8; 32];
        hh.copy_from_slice(&handshake_hash);

        // 派生会话密钥
        let client_keys = SessionKeys::derive(&client_shared, &hh);
        let server_keys = SessionKeys::derive(&server_shared, &hh);

        // 客户端用 client_write_key 加密
        let nonce = aead::generate_nonce();
        let plaintext = b"Hello from client!";
        let (ct, tag) = aead::encrypt(&client_keys.client_write_key, &nonce, b"", plaintext);

        // 服务端用 client_write_key 解密（同一个密钥）
        let decrypted = aead::decrypt(&server_keys.client_write_key, &nonce, b"", &ct, &tag).unwrap();
        assert_eq!(decrypted, plaintext);

        // 服务端用 server_write_key 加密回复
        let nonce2 = aead::generate_nonce();
        let reply = b"Hello from server!";
        let (ct2, tag2) = aead::encrypt(&server_keys.server_write_key, &nonce2, b"", reply);

        // 客户端用 server_write_key 解密
        let decrypted2 = aead::decrypt(&client_keys.server_write_key, &nonce2, b"", &ct2, &tag2).unwrap();
        assert_eq!(decrypted2, reply);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; 32];
        let nonce = aead::generate_nonce();
        let (ct, tag) = aead::encrypt(&key, &nonce, b"", b"");
        let decrypted = aead::decrypt(&key, &nonce, b"", &ct, &tag).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_plaintext() {
        let key = [0x42u8; 32];
        let nonce = aead::generate_nonce();
        let plaintext = vec![0xABu8; 1024 * 1024]; // 1MB

        let (ct, tag) = aead::encrypt(&key, &nonce, b"", &plaintext);
        let decrypted = aead::decrypt(&key, &nonce, b"", &ct, &tag).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
