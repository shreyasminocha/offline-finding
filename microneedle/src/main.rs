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
use offline_finding::{
    accessory::{Accessory, LegitAirtag},
    protocol::{OfflineFindingPublicKey, BleAdvertisementMetadata},
};

use defmt_rtt as _;
use panic_probe as _;

use microneedle::sdrng::SoftdeviceRng;

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

    let mut accessory = LegitAirtag::random(&mut SoftdeviceRng);

    info!(
        "master beacon private key: {}",
        base64
            .encode(accessory.get_master_private_key().to_bytes())
            .as_str(),
    );
    info!(
        "master beacon symmetric key: {}",
        base64.encode(accessory.get_master_symmetric_key()).as_str()
    );

    let mut ticker = Ticker::every(Duration::from_secs(KEY_ROTATION_PERIOD_SECONDS));
    loop {
        let public_key = accessory.get_current_public_key();

        debug!(
            "\nhashed ephemeral public key: {} ({})",
            base64.encode(public_key.hash()).as_str(),
            hex::encode_upper(public_key.to_ble_address_bytes_be()).as_str(),
        );

        let mut tick = ticker.next();
        let adv_future = broadcast_advertisement(sd, &public_key);
        pin.toggle();

        accessory.rotate_keys();

        match select(&mut tick, adv_future).await {
            Either::First(_) => continue, // ticker expired
            Either::Second(Result::Err(err)) => warn!("error advertizing: {:?}", err),
            Either::Second(Result::Ok(_)) => (),
        };
        tick.await;
    }
}

async fn broadcast_advertisement(
    sd: &Softdevice,
    public_key: &OfflineFindingPublicKey,
) -> Result<(), AdvertiseError> {
    let config = peripheral::Config {
        interval: ADVERTISING_INTERVAL_625_NS_UNITS,
        ..Default::default()
    };

    let mut ble_addr_le = public_key.to_ble_address_bytes_be();
    ble_addr_le.reverse();

    ble::set_address(
        sd,
        &ble::Address::new(ble::AddressType::Public, ble_addr_le),
    );

    let adv_data = LegacyAdvertisementBuilder::new()
        .raw(
            AdvertisementDataType::MANUFACTURER_SPECIFIC_DATA,
            &public_key.to_ble_advertisement_data(BleAdvertisementMetadata::default()),
        )
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

    peripheral::advertise(sd, adv, &config).await
}
