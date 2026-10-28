//! Public contracts without NetworkManager, Unix IPC or a kernel TUN device.
mod contracts {
    mod capabilities;
    mod fakeip;
    mod runtime;
    mod source_names;
    mod support;
}
