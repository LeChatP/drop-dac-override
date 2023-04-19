use aya::{programs::Lsm, Btf};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, warn};
use tokio::signal;

use std::process;


#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let pid = process::id() as i32;
    info!("PID: {}", pid);

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/drop-dac-override"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/drop-dac-override"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = bpf.program_mut("capable").unwrap().try_into()?;
    program.load("capable", &btf)?;
    program.attach()?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
