//! Embed the application icon into the Windows executable resource
//! section. Without it, the window/taskbar shows the generic blank
//! executable icon. On non-Windows targets this is a no-op.

fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("assets/icon.ico")
            .set("ProductName", "ASC Instant Workbench")
            .compile()
            .expect("embed windows icon resource");
    }
}
