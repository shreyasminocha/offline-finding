#![no_std]
#![no_main]

use defmt::*;
use embassy_executor::Spawner;
use embassy_time::{Duration, Ticker};
use nrf_softdevice::{
    ble::{
        self,
        advertisement_builder::{AdvertisementDataType, LegacyAdvertisementBuilder},
        peripheral::{self, AdvertiseError},
    },
    raw, Softdevice,
};

use defmt_rtt as _;
use panic_probe as _;

#[embassy_executor::task]
async fn softdevice_task(sd: &'static Softdevice) -> ! {
    sd.run().await
}

const NAME: &[u8] = b"needle";

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = embassy_nrf::config::Config::default();
    config.time_interrupt_priority = embassy_nrf::interrupt::Priority::P2;
    let _ = embassy_nrf::init(config);

    let config = nrf_softdevice::Config {
        clock: Some(raw::nrf_clock_lf_cfg_t {
            source: raw::NRF_CLOCK_LF_SRC_RC as u8,
            rc_ctiv: 16,
            rc_temp_ctiv: 2,
            accuracy: raw::NRF_CLOCK_LF_ACCURACY_500_PPM as u8,
        }),
        conn_gap: Some(raw::ble_gap_conn_cfg_t {
            conn_count: 0,
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
            current_len: NAME.len().try_into().unwrap(),
            max_len: 256,
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

    let mut ticker = Ticker::every(Duration::from_secs(2));
    loop {
        let key: &[u8; 28] = b"super secret unguessable key";
        // TODO generate new keys at random. Or with a hash??
        unwrap!(change_advertisement(sd, key).await);
        ticker.next().await;
    }
}

async fn change_advertisement(sd: &Softdevice, key: &[u8; 28]) -> Result<(), AdvertiseError> {
    // Set the address as the first 6 bytes of the key
    let mut bytes: [u8; 6] = (&key[0..6]).try_into().unwrap();
    bytes[0] |= 0b11000000;
    let addr = ble::Address::new(ble::AddressType::RandomStatic, bytes);

    // From the OpenHaystack paper
    let mut data: [u8; 28] = [
        0x4c, 0x00, // Apple company ID
        0x12, // Offline finding
        25,   // Length of following data
        0,    // Status (e.g. battery level) TODO put something here??
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // last 22 key bytes
        0, // first two bytes of key
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
        interval: 50,
        ..Default::default()
    };

    ble::set_address(sd, &addr);
    peripheral::advertise(sd, adv, &config).await
}
