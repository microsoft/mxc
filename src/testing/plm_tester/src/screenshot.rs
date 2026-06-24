//! screenshot — capture a display or window chosen by the user via the
//! system `GraphicsCapturePicker` and write the result to a PNG file.
//!
//! Usage: screenshot [output.png]
//!
//! Default output path is `screenshot.png` in the current directory.
//!
//! Why the picker instead of `CreateForMonitor`?
//!   `IGraphicsCaptureItemInterop::CreateForMonitor` (and `CreateForWindow`)
//!   require the caller's token to carry the `graphicsCaptureProgrammatic`
//!   capability when running in an AppContainer / LPAC. That capability
//!   check is performed inside the capture broker (DWM), not via a
//!   securable-object ACL, so AppContainer "permissive / learning" mode
//!   does NOT relax it -- the call still fails with E_ACCESSDENIED
//!   (0x80070005). The picker route is gated by the user-consent gesture
//!   instead, so it works from an AppContainer without that capability.
//!
//! Pipeline:
//!   1. Initialize the WinRT MTA apartment.
//!   2. Show `GraphicsCapturePicker` and wait for the user to pick a
//!      monitor or window.
//!   3. Create a D3D11 device + DXGI-backed `IDirect3DDevice`.
//!   4. Create a free-threaded `Direct3D11CaptureFramePool` and a
//!      `GraphicsCaptureSession` over it.
//!   5. Subscribe to FrameArrived, start the session, and wait for one
//!      frame on a channel.
//!   6. Copy the frame's GPU texture into a CPU-readable staging texture,
//!      map it, and re-pack BGRA -> RGBA into an `image::RgbaImage`.
//!   7. Save as PNG.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use windows::core::Interface;
use windows::Foundation::TypedEventHandler;
use windows::Graphics::Capture::{
    Direct3D11CaptureFramePool, GraphicsCaptureItem, GraphicsCapturePicker,
};
use windows::Graphics::DirectX::Direct3D11::IDirect3DDevice;
use windows::Graphics::DirectX::DirectXPixelFormat;
use windows::Win32::Foundation::HWND;
use windows::Win32::Graphics::Direct3D::{
    D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_10_0, D3D_FEATURE_LEVEL_11_0,
};
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
    D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAP_READ,
    D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::IDXGIDevice;
use windows::Win32::System::Console::GetConsoleWindow;
use windows::Win32::System::WinRT::Direct3D11::{
    CreateDirect3D11DeviceFromDXGIDevice, IDirect3DDxgiInterfaceAccess,
};
use windows::Win32::System::WinRT::{RoInitialize, RO_INIT_MULTITHREADED};
use windows::Win32::UI::Shell::IInitializeWithWindow;
use windows::Win32::UI::WindowsAndMessaging::GetDesktopWindow;

fn picker_owner_hwnd() -> HWND {
    // IInitializeWithWindow requires a real top-level HWND so the
    // picker can parent itself for modality. Prefer the console window
    // (this is a console-subsystem binary). Fall back to the desktop
    // window if no console is attached.
    let hwnd = unsafe { GetConsoleWindow() };
    if !hwnd.0.is_null() {
        return hwnd;
    }
    unsafe { GetDesktopWindow() }
}

fn pick_capture_item() -> Result<GraphicsCaptureItem> {
    let picker = GraphicsCapturePicker::new().context("GraphicsCapturePicker::new failed")?;

    let init: IInitializeWithWindow = picker
        .cast()
        .context("GraphicsCapturePicker -> IInitializeWithWindow cast failed")?;
    let owner = picker_owner_hwnd();
    eprintln!("[step] associating picker with HWND {:?}", owner.0);
    unsafe {
        init.Initialize(owner)
            .context("IInitializeWithWindow::Initialize failed")?;
    }

    eprintln!("[step] PickSingleItemAsync (waiting for user selection)");
    let op = picker
        .PickSingleItemAsync()
        .context("PickSingleItemAsync failed to start")?;
    let item = op
        .get()
        .context("PickSingleItemAsync awaited result failed")?;

    // A cancelled picker yields a null GraphicsCaptureItem.
    if item.as_raw().is_null() {
        return Err(anyhow!("user cancelled the capture picker"));
    }
    Ok(item)
}

fn create_d3d11_device() -> Result<(ID3D11Device, ID3D11DeviceContext)> {
    let mut device: Option<ID3D11Device> = None;
    let mut context: Option<ID3D11DeviceContext> = None;
    let mut chosen_level = D3D_FEATURE_LEVEL_11_0;
    let feature_levels = [D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0];

    unsafe {
        D3D11CreateDevice(
            None,
            D3D_DRIVER_TYPE_HARDWARE,
            None,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            Some(&feature_levels),
            D3D11_SDK_VERSION,
            Some(&mut device),
            Some(&mut chosen_level),
            Some(&mut context),
        )
        .context("D3D11CreateDevice failed")?;
    }
    Ok((
        device.ok_or_else(|| anyhow!("D3D11CreateDevice did not return a device"))?,
        context.ok_or_else(|| anyhow!("D3D11CreateDevice did not return a context"))?,
    ))
}

fn d3d11_device_to_winrt(device: &ID3D11Device) -> Result<IDirect3DDevice> {
    let dxgi: IDXGIDevice = device.cast().context("ID3D11Device -> IDXGIDevice cast failed")?;
    let inspectable = unsafe {
        CreateDirect3D11DeviceFromDXGIDevice(&dxgi)
            .context("CreateDirect3D11DeviceFromDXGIDevice failed")?
    };
    inspectable
        .cast::<IDirect3DDevice>()
        .context("IInspectable -> IDirect3DDevice cast failed")
}

fn frame_texture(frame: &windows::Graphics::Capture::Direct3D11CaptureFrame) -> Result<ID3D11Texture2D> {
    let surface = frame.Surface().context("Frame Surface() failed")?;
    let access: IDirect3DDxgiInterfaceAccess = surface
        .cast()
        .context("IDirect3DSurface -> IDirect3DDxgiInterfaceAccess cast failed")?;
    let texture: ID3D11Texture2D = unsafe {
        access
            .GetInterface::<ID3D11Texture2D>()
            .context("GetInterface<ID3D11Texture2D> failed")?
    };
    Ok(texture)
}

fn save_png(path: &std::path::Path, width: u32, height: u32, bgra: &[u8]) -> Result<()> {
    let mut rgba = Vec::with_capacity(bgra.len());
    for chunk in bgra.chunks_exact(4) {
        rgba.extend_from_slice(&[chunk[2], chunk[1], chunk[0], chunk[3]]);
    }
    let img = image::RgbaImage::from_raw(width, height, rgba)
        .ok_or_else(|| anyhow!("failed to construct image buffer"))?;
    img.save(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn main_impl(out_path: PathBuf) -> Result<(u32, u32)> {
    eprintln!("[step] output path: {}", out_path.display());

    eprintln!("[step] RoInitialize(MULTITHREADED)");
    unsafe {
        RoInitialize(RO_INIT_MULTITHREADED).context("RoInitialize failed")?;
    }
    eprintln!("[ok]   RoInitialize");

    eprintln!("[step] launching GraphicsCapturePicker");
    let item = pick_capture_item()?;
    let size = item.Size().context("GraphicsCaptureItem Size() failed")?;
    let name = item.DisplayName().ok().map(|h| h.to_string_lossy()).unwrap_or_default();
    eprintln!("[ok]   picked item: {:?} ({}x{})", name, size.Width, size.Height);

    eprintln!("[step] creating D3D11 device");
    let (d3d_device, d3d_context) = create_d3d11_device()?;
    eprintln!("[ok]   D3D11 device + context");

    eprintln!("[step] wrapping device as IDirect3DDevice (WinRT)");
    let winrt_device = d3d11_device_to_winrt(&d3d_device)?;
    eprintln!("[ok]   IDirect3DDevice");

    eprintln!("[step] CreateFreeThreaded frame pool ({}x{}, BGRA8)", size.Width, size.Height);
    let frame_pool = Direct3D11CaptureFramePool::CreateFreeThreaded(
        &winrt_device,
        DirectXPixelFormat::B8G8R8A8UIntNormalized,
        2,
        size,
    )
    .context("CreateFreeThreaded framepool failed")?;
    eprintln!("[ok]   frame pool created");

    eprintln!("[step] CreateCaptureSession");
    let session = frame_pool
        .CreateCaptureSession(&item)
        .context("CreateCaptureSession failed")?;
    eprintln!("[ok]   capture session created");

    eprintln!("[step] subscribing to FrameArrived");
    let (tx, rx) = mpsc::sync_channel::<()>(1);
    let captured: std::sync::Arc<std::sync::Mutex<Option<windows::Graphics::Capture::Direct3D11CaptureFrame>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));
    let captured_h = captured.clone();
    let tx_h = tx.clone();
    let handler =
        TypedEventHandler::<Direct3D11CaptureFramePool, windows::core::IInspectable>::new(
            move |sender, _| {
                if let Some(pool) = sender.as_ref() {
                    if let Ok(frame) = pool.TryGetNextFrame() {
                        let mut slot = captured_h.lock().unwrap();
                        if slot.is_none() {
                            *slot = Some(frame);
                            let _ = tx_h.try_send(());
                        }
                    }
                }
                Ok(())
            },
        );
    let _token = frame_pool
        .FrameArrived(&handler)
        .context("FrameArrived subscription failed")?;
    eprintln!("[ok]   FrameArrived handler registered");

    eprintln!("[step] StartCapture");
    session.StartCapture().context("StartCapture failed")?;
    eprintln!("[ok]   capture started");

    eprintln!("[step] waiting up to 5s for first frame");
    rx.recv_timeout(Duration::from_secs(5))
        .context("timed out waiting for first frame")?;
    eprintln!("[ok]   frame signalled");

    let frame = captured
        .lock()
        .unwrap()
        .take()
        .ok_or_else(|| anyhow!("frame slot empty after signal"))?;
    eprintln!("[ok]   frame retrieved from slot");

    let frame_size = frame.ContentSize().context("ContentSize() failed")?;
    eprintln!("[ok]   ContentSize = {}x{}", frame_size.Width, frame_size.Height);

    eprintln!("[step] extracting ID3D11Texture2D from frame surface");
    let texture = frame_texture(&frame)?;
    eprintln!("[ok]   texture handle obtained");

    eprintln!("[step] creating CPU-readable staging texture");
    let mut desc = D3D11_TEXTURE2D_DESC::default();
    unsafe { texture.GetDesc(&mut desc) };
    desc.Usage = D3D11_USAGE_STAGING;
    desc.BindFlags = 0;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ.0 as u32;
    desc.MiscFlags = 0;

    let mut staging: Option<ID3D11Texture2D> = None;
    unsafe {
        d3d_device
            .CreateTexture2D(&desc, None, Some(&mut staging))
            .context("CreateTexture2D (staging) failed")?;
    }
    let staging = staging.ok_or_else(|| anyhow!("staging texture not created"))?;
    eprintln!("[ok]   staging texture created");

    eprintln!("[step] CopyResource GPU -> staging");
    unsafe { d3d_context.CopyResource(&staging, &texture) };
    eprintln!("[ok]   CopyResource issued");

    eprintln!("[step] Map staging for CPU read");
    let mut mapped = windows::Win32::Graphics::Direct3D11::D3D11_MAPPED_SUBRESOURCE::default();
    unsafe {
        d3d_context
            .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
            .context("ID3D11DeviceContext::Map failed")?;
    }
    eprintln!("[ok]   mapped (RowPitch={})", mapped.RowPitch);

    let width = frame_size.Width as u32;
    let height = frame_size.Height as u32;
    let row_bytes = (width * 4) as usize;
    eprintln!(
        "[step] copying {} rows x {} bytes from mapped buffer",
        height, row_bytes
    );
    let mut tight = Vec::with_capacity(row_bytes * height as usize);
    unsafe {
        let base = mapped.pData as *const u8;
        for y in 0..height as usize {
            let src = base.add(y * mapped.RowPitch as usize);
            let row = std::slice::from_raw_parts(src, row_bytes);
            tight.extend_from_slice(row);
        }
        d3d_context.Unmap(&staging, 0);
    }
    eprintln!("[ok]   pixels copied ({} bytes), Unmap done", tight.len());

    eprintln!("[step] encoding + writing PNG to {}", out_path.display());
    save_png(&out_path, width, height, &tight)?;
    eprintln!("[ok]   PNG written");
    Ok((width, height))
}

/// Public entry: capture via Windows.Graphics.Capture picker and write
/// to `out_path`. Returns `(width, height)`.
pub fn capture(out_path: &Path) -> Result<(u32, u32)> {
    main_impl(out_path.to_path_buf())
}
