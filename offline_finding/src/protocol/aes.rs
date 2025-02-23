use aes_gcm::{aes::Aes128, AesGcm};
use sha2::digest::consts::U16;

pub type Aes = AesGcm<Aes128, U16>;
