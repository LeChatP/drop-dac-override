# drop-dac-override

This project is a PoC to show that it is possible to remove permanently the DAC override on system. 

## Kernel Module way

This project propose a kernel module (in drop-dac-override-kmod) which is removing capability when execve called. In other terms, if this kernel module is loaded on init, even PID 1 will loose the capability. So any new process could not use tricks to elevate this privilege. And so, he could not bypass DAC policy. Use it at your own risks. becare of any DAC misconfiguration will, loose definitely a file. In that case, you need to start a rescur mode alternative.
To recover the initial state, you should remove module from initied modules, then you need to reboot.

### Prerequisites

The kernel compiler (gcc mostly, or clang). You'll also need make.

### Build Module

```bash
make all
```

It will create dropper_mod.ko file.

### Run

```bash
sudo insmod dropper_mod.ko
```

In this running case, any new process will loose DAC privileges. To setup it at boot time, you'll need to refer to your distro documentation.

## eBPF way

This project present a LSM BPF which refuse any DAC capability asks. In this case, when BPF is enforced, process still has the capability in their creds. The result is quite the same than Kernel Module, but if you could disable eBPF, the privilege will be recovered during the current boot instance (no need to reboot).

### Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain with the rust-src component: `rustup toolchain install nightly --component rust-src`
1. Install bpf-linker: `cargo install bpf-linker`

### Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

### Build Userspace

```bash
cargo build
```

### Run

```bash
RUST_LOG=info cargo xtask run
```
