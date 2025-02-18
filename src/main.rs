#![no_std]
#![no_main]

use defmt::*;
use embassy_executor::Spawner;
use embassy_futures::select::{select, Either};
use embassy_nrf::{
    gpio::{Level, Output, OutputDrive},
    interrupt,
};
use embassy_time::{Duration, Ticker};
use embedded_alloc::LlffHeap as Heap;
use nrf_softdevice::{
    ble::{
        self,
        advertisement_builder::{AdvertisementDataType, LegacyAdvertisementBuilder},
        peripheral::{self, AdvertiseError},
    },
    raw, Softdevice,
};

use base64::{engine::general_purpose::STANDARD as base64, Engine as _};
use num_bigint::BigUint;
use p224::{
    self,
    elliptic_curve::{bigint::Encoding, rand_core::RngCore, sec1::ToEncodedPoint, Curve},
    NistP224, SecretKey,
};
use sha2::{Digest, Sha256};

use defmt_rtt as _;
use panic_probe as _;

use needle::sdrng::SoftdeviceRng;

#[global_allocator]
static HEAP: Heap = Heap::empty();

#[embassy_executor::task]
async fn softdevice_task(sd: &'static Softdevice) -> ! {
    sd.run().await
}

const NAME: &[u8] = b"needle\0";
const NAME_LEN: u16 = NAME.len() as u16;

const KEY_ROTATION_PERIOD_SECONDS: u64 = 10;
// TOFIX: are the docs accurate about the unit?
const ADVERTISING_INTERVAL_625_NS_UNITS: u32 = 1000;

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    {
        use core::mem::MaybeUninit;
        const HEAP_SIZE: usize = 1024;
        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe { HEAP.init(&raw mut HEAP_MEM as usize, HEAP_SIZE) }
    }

    let mut config = embassy_nrf::config::Config::default();
    config.time_interrupt_priority = interrupt::Priority::P2;
    let p = embassy_nrf::init(config);

    let config = nrf_softdevice::Config {
        clock: Some(raw::nrf_clock_lf_cfg_t {
            source: raw::NRF_CLOCK_LF_SRC_RC as u8,
            rc_ctiv: 16,
            rc_temp_ctiv: 2,
            accuracy: raw::NRF_CLOCK_LF_ACCURACY_500_PPM as u8,
        }),
        conn_gap: Some(raw::ble_gap_conn_cfg_t {
            conn_count: 1,
            event_length: 24,
        }),
        conn_gatt: Some(raw::ble_gatt_conn_cfg_t { att_mtu: 256 }),
        gatts_attr_tab_size: Some(raw::ble_gatts_cfg_attr_tab_size_t {
            attr_tab_size: raw::BLE_GATTS_ATTR_TAB_SIZE_DEFAULT,
        }),
        gap_role_count: Some(raw::ble_gap_cfg_role_count_t {
            adv_set_count: 1,
            periph_role_count: 3,
            central_role_count: 3,
            central_sec_count: 0,
            _bitfield_1: raw::ble_gap_cfg_role_count_t::new_bitfield_1(0),
        }),
        gap_device_name: Some(raw::ble_gap_cfg_device_name_t {
            p_value: NAME.as_ptr() as _,
            current_len: NAME_LEN,
            max_len: NAME_LEN,
            write_perm: raw::ble_gap_conn_sec_mode_t {
                // disable write permissions
                _bitfield_1: raw::ble_gap_conn_sec_mode_t::new_bitfield_1(0, 0),
            },
            _bitfield_1: raw::ble_gap_cfg_device_name_t::new_bitfield_1(
                raw::BLE_GATTS_VLOC_USER as u8,
            ),
        }),
        ..Default::default()
    };

    let sd = Softdevice::enable(&config);
    unwrap!(spawner.spawn(softdevice_task(sd)));

    let col = Output::new(p.P0_31, Level::Low, OutputDrive::Standard);
    let _ = col;
    let mut pin = Output::new(p.P0_15, Level::Low, OutputDrive::Standard);

    let mb_private_key = SecretKey::random(&mut SoftdeviceRng);
    let _mb_public_key = mb_private_key.public_key();

    let mut mb_symmetric_key = [0; 32];
    SoftdeviceRng.fill_bytes(&mut mb_symmetric_key);

    info!(
        "master beacon private key: {}\nmaster beacon symmetric key: {}",
        base64.encode(mb_private_key.to_bytes()).as_str(),
        base64.encode(mb_symmetric_key).as_str()
    );

    let mut sk_i = mb_symmetric_key;

    let mut ticker = Ticker::every(Duration::from_secs(KEY_ROTATION_PERIOD_SECONDS));
    loop {
        let (ad_private_key, new_sk) = generate_next_ephemeral_keys(&mb_private_key, &sk_i);
        sk_i = new_sk;

        // equation 4
        let ad_public_key = ad_private_key.public_key();

        let ad_public_key_point = ad_public_key.to_encoded_point(true);
        let key: [u8; 28] = ad_public_key_point
            .x()
            .unwrap()
            .as_slice()
            .try_into()
            .expect("the x coordinate of a P224 point must be 28 bytes long");

        let mut hasher = Sha256::new();
        hasher.update(key);
        let hash = hasher.finalize();

        debug!(
            "\nhashed ephemeral public key: {}\nbluetooth mac address: {}",
            base64.encode(hash).as_str(),
            key_to_ble_mac_address(&key),
        );

        let mut tick = ticker.next();
        let adv_future = change_advertisement(sd, &key);
        pin.toggle();

        match select(&mut tick, adv_future).await {
            Either::First(_) => continue, // ticker expired
            Either::Second(Result::Err(err)) => warn!("error advertizing: {:?}", err),
            Either::Second(Result::Ok(_)) => (),
        };
        tick.await;
    }
}

async fn change_advertisement(sd: &Softdevice, key: &[u8; 28]) -> Result<(), AdvertiseError> {
    // From the OpenHaystack paper
    let mut data: [u8; 29] = [
        0x4c, 0x00,       // Apple company ID
        0x12,       // Offline finding
        25,         // Length of following data
        0b11100000, // Status (e.g. battery level)
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // last 22 key bytes
        0, // first two bits of key
        0, // Hint. Indicates something about the lost device? 0x00 for iOS reports
    ];
    data[5..27].copy_from_slice(&key[6..]);
    data[27] = key[0] >> 6;

    let adv_data = LegacyAdvertisementBuilder::new()
        .raw(AdvertisementDataType::MANUFACTURER_SPECIFIC_DATA, &data)
        .build();
    defmt::debug_assert_eq!(adv_data[0], 30, "adv_data was not 30 bytes");
    defmt::debug_assert_eq!(
        adv_data[1],
        0xff,
        "LegacyAdvertisementBuider did not set manufacturer data correctly"
    );

    let adv = peripheral::NonconnectableAdvertisement::NonscannableUndirected {
        adv_data: &adv_data,
    };
    let config = peripheral::Config {
        interval: ADVERTISING_INTERVAL_625_NS_UNITS,
        ..Default::default()
    };

    ble::set_address(sd, &key_to_ble_mac_address(key));
    peripheral::advertise(sd, adv, &config).await
}

fn generate_next_ephemeral_keys(
    mb_private_key: &SecretKey,
    last_symmetric_key: &[u8; 32],
) -> (SecretKey, [u8; 32]) {
    // equation 1
    let mut new_symmetric_key = [0u8; 32];
    ansi_x963_kdf::derive_key_into::<Sha256>(last_symmetric_key, b"update", &mut new_symmetric_key)
        .unwrap();

    // equation 2
    let mut uv = [0u8; 72];
    ansi_x963_kdf::derive_key_into::<Sha256>(&new_symmetric_key, b"diversify", &mut uv).unwrap();

    let (u, v) = uv.split_at(36);

    // https://github.com/positive-security/find-you/blob/ab7a3a9/OpenHaystack/OpenHaystack/BoringSSL/BoringSSL.m#L194
    let order = &BigUint::from_bytes_be(&NistP224::ORDER.to_be_bytes());
    let order_minus_one = &(order - BigUint::from(1u8));
    let u_i = (BigUint::from_bytes_be(u) % order_minus_one) + BigUint::from(1u8);
    let v_i = (BigUint::from_bytes_be(v) % order_minus_one) + BigUint::from(1u8);

    let d_0 = BigUint::from_bytes_be(mb_private_key.to_bytes().as_slice());

    // equation 3
    let d_i = (d_0 * u_i) + v_i;
    let d_i = d_i % order;
    let ephemeral_private_key = SecretKey::from_slice(&d_i.to_bytes_be()).unwrap();

    (ephemeral_private_key, new_symmetric_key)
}

fn key_to_ble_mac_address(key: &[u8; 28]) -> ble::Address {
    // Set the address as the first 6 bytes of the key
    let mut addr_bytes_be: [u8; 6] = key
        .get(0..6)
        .expect("6 <= 28")
        .try_into()
        .expect("there are exactly six elements in the slice");
    addr_bytes_be[0] |= 0b11000000;

    let mut addr_bytes_le = addr_bytes_be;
    addr_bytes_le.reverse();

    ble::Address::new(ble::AddressType::Public, addr_bytes_le)
}
