use core::num::NonZeroU32;

use nrf_softdevice::raw::{
    sd_rand_application_bytes_available_get, sd_rand_application_vector_get, NRF_SUCCESS,
};
use offline_finding::p224::elliptic_curve::rand_core::{CryptoRng, Error, RngCore};

pub struct SoftdeviceRng;

impl RngCore for SoftdeviceRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0; 4];
        self.fill_bytes(&mut buf);

        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0; 8];
        self.fill_bytes(&mut buf);

        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // we'd rather panic than give bad bytes
        self.try_fill_bytes(dest).unwrap()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        let mut i = 0;
        while i < dest.len() {
            let mut bytes_available = 0u8;
            unsafe {
                sd_rand_application_bytes_available_get(&mut bytes_available as *mut u8);
            }

            let chunk_size = (bytes_available as usize).min(dest.len() - i);

            let result: u32;
            unsafe {
                result = sd_rand_application_vector_get(
                    dest[i..].as_mut_ptr(),
                    chunk_size
                        .try_into()
                        .expect("it is at most the (u8) number of bytes available"),
                );
            }

            if result != NRF_SUCCESS {
                return Err(Error::from(
                    NonZeroU32::try_from(result).expect("we already checked that it's non-zero"),
                ));
            }

            i += chunk_size;
        }

        Ok(())
    }
}

// TODO: umm chat is this true?
impl CryptoRng for SoftdeviceRng {}
