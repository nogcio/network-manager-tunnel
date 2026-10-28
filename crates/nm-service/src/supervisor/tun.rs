//! Create a new kernel-allocated TUN, then atomically claim our public name.
use std::io;

/// An empty TUNSETIFF name creates a new device, never attaches by name. Linux
/// allocates its temporary name under RTNL. SIOCSIFNAME refuses an occupied target
/// atomically; on refusal only our new nonpersistent device is dropped. No
/// existence precheck, persistent device adoption or local unsafe code is used.
pub(super) fn create() -> io::Result<tun_rs::SyncDevice> {
    let device = tun_rs::DeviceBuilder::new()
        .enable(false)
        .packet_information(false)
        .offload(false)
        .build_sync()?;
    device.set_name("nmtun0")?;
    Ok(device)
}
