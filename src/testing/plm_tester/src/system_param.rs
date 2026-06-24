//! Minimal probe for `SystemParametersInfoW`.
//!
//! USER32's SystemParametersInfo is the legacy "read/write a user
//! preference" API. Different SPI_* actions have different param
//! shapes; we expose just a handful of well-typed ones so the
//! subcommand stays a flat `--action ... [--value ...]` interface.
//!
//! The interesting question for PLM / AppContainer is whether the
//! *set* variants — which write to HKCU and broadcast WM_SETTINGCHANGE
//! — are gated. Get variants almost always succeed.

use anyhow::{anyhow, Context, Result};
use clap::{Args, ValueEnum};

use windows::core::PWSTR;
use windows::Win32::Foundation::COLORREF;
use windows::Win32::Graphics::Gdi::SetSysColors;
use windows::Win32::UI::WindowsAndMessaging::{
    SystemParametersInfoW, SPIF_SENDCHANGE, SPIF_UPDATEINIFILE,
    SPI_GETDESKWALLPAPER, SPI_GETMOUSESPEED, SPI_GETSCREENSAVETIMEOUT, SPI_SETMOUSESPEED,
    SPI_SETSCREENSAVETIMEOUT, SYSTEM_PARAMETERS_INFO_ACTION,
    SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS,
};

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum SpiAction {
    /// SPI_GETMOUSESPEED — DWORD out (1..=20).
    GetMouseSpeed,
    /// SPI_SETMOUSESPEED — DWORD in (1..=20). Requires --value.
    SetMouseSpeed,
    /// SPI_GETSCREENSAVETIMEOUT — seconds out (DWORD).
    GetScreenSaverTimeout,
    /// SPI_SETSCREENSAVETIMEOUT — seconds in (DWORD). Requires --value.
    SetScreenSaverTimeout,
    /// SPI_GETDESKWALLPAPER — wide-char path out (MAX_PATH).
    GetWallpaper,
    /// SetSysColors(1, [index], [colorref]) — change a single element
    /// of the user's COLOR_* table. Requires --index and --value
    /// (--value is parsed as a COLORREF, i.e. 0x00BBGGRR). Broadcasts
    /// WM_SYSCOLORCHANGE; the per-user color table write is the part
    /// most likely to be blocked by PLM / AppContainer.
    SetSysColors,
}

#[derive(Args, Debug)]
pub struct SystemParamArgs {
    /// SPI_* action to invoke.
    #[arg(long, value_enum, default_value_t = SpiAction::GetMouseSpeed)]
    pub action: SpiAction,

    /// Value to pass for `set-*` actions (ignored by `get-*`). For
    /// `set-sys-colors` this is a COLORREF (0x00BBGGRR). Accepts
    /// decimal or 0x-prefixed hex.
    #[arg(long, value_parser = parse_u32_auto)]
    pub value: Option<u32>,

    /// COLOR_* index for `set-sys-colors`. See the SetSysColors
    /// documentation for the index values (e.g. 1 = COLOR_BACKGROUND,
    /// 5 = COLOR_WINDOW).
    #[arg(long)]
    pub index: Option<i32>,

    /// Also persist the change to HKCU (SPIF_UPDATEINIFILE) and
    /// broadcast WM_SETTINGCHANGE (SPIF_SENDCHANGE). Only meaningful
    /// for `set-*` SPI_* actions. `set-sys-colors` always broadcasts
    /// WM_SYSCOLORCHANGE on success regardless of this flag.
    #[arg(long, default_value_t = false)]
    pub persist: bool,
}

fn parse_u32_auto(s: &str) -> Result<u32, String> {
    let t = s.trim();
    let (radix, digits) = if let Some(rest) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        (16, rest)
    } else {
        (10, t)
    };
    u32::from_str_radix(digits, radix).map_err(|e| format!("invalid u32 {s:?}: {e}"))
}

unsafe fn spi(
    action: SYSTEM_PARAMETERS_INFO_ACTION,
    uiparam: u32,
    pvparam: Option<*mut core::ffi::c_void>,
    flags: SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS,
) -> Result<()> {
    SystemParametersInfoW(action, uiparam, pvparam, flags)
        .with_context(|| format!("SystemParametersInfoW(0x{:04X}) failed", action.0))
}

pub fn run(args: SystemParamArgs) -> Result<()> {
    let SystemParamArgs {
        action,
        value,
        index,
        persist,
    } = args;

    let set_flags = if persist {
        SPIF_UPDATEINIFILE | SPIF_SENDCHANGE
    } else {
        SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0)
    };
    let no_flags = SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0);

    match action {
        SpiAction::GetMouseSpeed => unsafe {
            let mut speed: u32 = 0;
            spi(
                SPI_GETMOUSESPEED,
                0,
                Some(&mut speed as *mut _ as *mut _),
                no_flags,
            )?;
            eprintln!("[ok]   SPI_GETMOUSESPEED");
            println!("mouse_speed = {speed}  (range 1..=20)");
        },
        SpiAction::SetMouseSpeed => {
            let v = value.ok_or_else(|| anyhow!("--value required for set-mouse-speed (1..=20)"))?;
            if !(1..=20).contains(&v) {
                return Err(anyhow!("--value must be in 1..=20, got {v}"));
            }
            unsafe {
                // SPI_SETMOUSESPEED takes the new speed in pvParam as a
                // DWORD-sized integer cast to a pointer (not via the
                // buffer). Pass the value directly.
                spi(
                    SPI_SETMOUSESPEED,
                    0,
                    Some(v as usize as *mut _),
                    set_flags,
                )?;
            }
            eprintln!("[ok]   SPI_SETMOUSESPEED -> {v} (persist={persist})");
        }
        SpiAction::GetScreenSaverTimeout => unsafe {
            let mut secs: u32 = 0;
            spi(
                SPI_GETSCREENSAVETIMEOUT,
                0,
                Some(&mut secs as *mut _ as *mut _),
                no_flags,
            )?;
            eprintln!("[ok]   SPI_GETSCREENSAVETIMEOUT");
            println!("screensaver_timeout = {secs} s");
        },
        SpiAction::SetScreenSaverTimeout => {
            let v = value
                .ok_or_else(|| anyhow!("--value required for set-screen-saver-timeout (seconds)"))?;
            unsafe {
                spi(
                    SPI_SETSCREENSAVETIMEOUT,
                    v,
                    None,
                    set_flags,
                )?;
            }
            eprintln!("[ok]   SPI_SETSCREENSAVETIMEOUT -> {v}s (persist={persist})");
        }
        SpiAction::GetWallpaper => unsafe {
            let mut buf = [0u16; 260 /* MAX_PATH */];
            spi(
                SPI_GETDESKWALLPAPER,
                buf.len() as u32,
                Some(buf.as_mut_ptr() as *mut _),
                no_flags,
            )?;
            let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            let path = String::from_utf16_lossy(&buf[..n]);
            eprintln!("[ok]   SPI_GETDESKWALLPAPER");
            println!("wallpaper = {path}");
            // Suppress unused-warning for the typed PWSTR import.
            let _ = PWSTR::null();
        },
        SpiAction::SetSysColors => {
            let idx = index.ok_or_else(|| {
                anyhow!("--index required for set-sys-colors (e.g. 1 = COLOR_BACKGROUND)")
            })?;
            let v = value.ok_or_else(|| {
                anyhow!("--value required for set-sys-colors (COLORREF, e.g. 0x00112233)")
            })?;
            let indices: [i32; 1] = [idx];
            let colors: [COLORREF; 1] = [COLORREF(v)];
            let rc = unsafe { SetSysColors(1, indices.as_ptr(), colors.as_ptr()) };
            if let Err(e) = rc {
                return Err(anyhow!(
                    "SetSysColors(index={idx}, color=0x{v:08X}) failed: {e}"
                ));
            }
            eprintln!(
                "[ok]   SetSysColors(index={idx}, color=0x{v:08X}) (persist flag ignored — \
                 SetSysColors always broadcasts WM_SYSCOLORCHANGE)"
            );
            let _ = persist;
        }
    }

    Ok(())
}
