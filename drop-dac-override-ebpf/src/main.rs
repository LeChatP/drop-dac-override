#![no_std]
#![no_main]

use aya_log_ebpf::info;

use aya_bpf::{
    macros::lsm,
    programs::LsmContext, cty::c_int,
};



const CAP_DAC_OVERRIDE: i32 = 1;
const CAP_DAC_READ_SEARCH: i32 = 2;

#[lsm(name = "capable")]
pub fn capable(ctx: LsmContext) -> i32 {
    match unsafe { try_capable(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_capable(ctx: LsmContext) -> Result<i32, i32> {
    let capability: c_int = ctx.arg(2);

    // If previous eBPF LSM program didn't allow the action, return the
    // previous error code.
    if capability == CAP_DAC_OVERRIDE || capability == CAP_DAC_READ_SEARCH {
        info!(&ctx,"capable: Blocking CAP_DAC_OVERRIDE");
        return Err(-1);
    }
    return Ok(0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
