#![no_std]
#![no_main]

mod fd_ident;
mod filter;
mod helpers;
mod layer1_tty;
mod layer2_exec;
mod layer3_raw;
mod layer3_rich;
mod lsm_hooks;
mod maps;
mod packet_tc;
mod vmlinux;

// ── Global Variables ─────────────────────────────────────────────────────────

#[no_mangle]
pub static mut TARGET_AUID: u32 = u32::MAX;

#[no_mangle]
pub static mut DROP_COUNT: u64 = 0;

#[no_mangle]
pub static mut DAEMON_PID: u32 = 0;

// ── Panic Handler ────────────────────────────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
