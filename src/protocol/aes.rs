use aes_gcm::{aes::Aes128, AesGcm};
use sha2_pre::digest::consts::U16;

/// AES as used in the encryption and decryption of FIndMy reports: AES-128 in GCM mode.
pub type Aes = AesGcm<Aes128, U16>;
