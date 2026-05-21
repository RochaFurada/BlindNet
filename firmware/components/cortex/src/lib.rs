#![no_std]

pub mod boot;
pub mod conscience;
pub mod ffi;
pub mod logic;
pub mod platform;

use core::panic::PanicInfo;

#[no_mangle]
pub extern "C" fn blindnet_boot() -> i32 {
    boot::run()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
