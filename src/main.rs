#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

use constants::*;
use panic_probe as _;

mod constants;
mod tasks;

static mut RNG: embassy_rp::clocks::RoscRng = embassy_rp::clocks::RoscRng;

fn get_random_implementation(destination: &mut [u8]) -> core::result::Result<(), getrandom::Error> {
    unsafe {
        rand_core::RngCore::fill_bytes(&mut RNG, destination);
    }

    core::result::Result::Ok(())
}

getrandom::register_custom_getrandom!(get_random_implementation);
embassy_rp::bind_interrupts!(struct IRQHandlerPIO0 {
    PIO0_IRQ_0 => embassy_rp::pio::InterruptHandler<embassy_rp::peripherals::PIO0>;
});
embassy_rp::bind_interrupts!(struct IRQHandlerUSB {
    USBCTRL_IRQ => embassy_rp::usb::InterruptHandler<embassy_rp::peripherals::USB>;
});

#[cortex_m_rt::entry]
fn entrypoint() -> ! {
    tasks::run()
}
