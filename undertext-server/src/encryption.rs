use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use rand::{Rng, RngCore};
use base64::{Engine as _, engine::general_purpose};
use tracing::{error, debug};

use crate::models::SubtitleBlock;

pub struct EncryptionManager {
    master_key: Key<Aes256Gcm>,
}

impl EncryptionManager {
    pub fn new(master_key_base64: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let key_bytes = general_purpose::STANDARD.decode(master_key_base64)?;
        if key_bytes.len() != 32 {
            return Err("Master key must be 32 bytes (256 bits)".into());
        }
        
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        Ok(EncryptionManager {
            master_key: *key,
        })
    }

    pub fn generate_session_key(&self) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let mut rng = rand::thread_rng();
        
        // Generate a random session key
        let mut session_key = vec![0u8; 32];
        rng.fill_bytes(&mut session_key);
        
        // Generate a random IV
        let mut iv = vec![0u8; 12];
        rng.fill_bytes(&mut iv);
        
        Ok((session_key, iv))
    }

    pub fn encrypt_subtitle_data(
        &self,
        data: &[u8],
        session_key: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(session_key));
        let nonce = Nonce::from_slice(iv);
        
        let encrypted = cipher
            .encrypt(nonce, data)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        debug!("Encrypted {} bytes of subtitle data", data.len());
        Ok(encrypted)
    }

    pub fn decrypt_subtitle_data(
        &self,
        encrypted_data: &[u8],
        session_key: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(session_key));
        let nonce = Nonce::from_slice(iv);
        
        let decrypted = cipher
            .decrypt(nonce, encrypted_data)
            .map_err(|e| format!("Decryption failed: {}", e))?;
        
        debug!("Decrypted {} bytes of subtitle data", encrypted_data.len());
        Ok(decrypted)
    }

    pub fn chunk_subtitle_data(&self, data: &[u8], chunk_size: usize) -> Vec<SubtitleBlock> {
        let mut chunks = Vec::new();
        let mut sequence = 0u32;
        
        for chunk in data.chunks(chunk_size) {
            chunks.push(SubtitleBlock {
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                data: chunk.to_vec(),
                sequence,
            });
            sequence += 1;
        }
        
        chunks
    }

    pub fn encode_key_for_transmission(&self, key: &[u8]) -> String {
        general_purpose::STANDARD.encode(key)
    }

    pub fn decode_key_from_transmission(&self, encoded_key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(general_purpose::STANDARD.decode(encoded_key)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_roundtrip() {
        let master_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let manager = EncryptionManager::new(master_key).unwrap();
        
        let test_data = b"Hello, Undertext!";
        let (session_key, iv) = manager.generate_session_key().unwrap();
        
        let encrypted = manager.encrypt_subtitle_data(test_data, &session_key, &iv).unwrap();
        let decrypted = manager.decrypt_subtitle_data(&encrypted, &session_key, &iv).unwrap();
        
        assert_eq!(test_data, decrypted.as_slice());
    }

    #[test]
    fn test_chunking() {
        let master_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let manager = EncryptionManager::new(master_key).unwrap();
        
        let test_data = b"This is a test subtitle that should be chunked into smaller pieces";
        let chunks = manager.chunk_subtitle_data(test_data, 16);
        
        assert!(!chunks.is_empty());
        assert_eq!(chunks[0].sequence, 0);
        assert_eq!(chunks[1].sequence, 1);
    }
} 