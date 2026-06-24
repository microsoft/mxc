//! Minimal probe for `ChangeDisplaySettingsW` (USER32).
//!
//! `ChangeDisplaySettings` is the legacy "change the primary display
//! mode" API. The interesting PLM / AppContainer question is whether
//! the change is allowed at all — most sandboxes block the registry /
//! broker path it walks through.
//!
//! By default this subcommand is **non-destructive**: it reads the
//! current mode with `EnumDisplaySettingsW(ENUM_CURRENT_SETTINGS)` and
//! re-submits it under `CDS_TEST`, which validates the call path
//! without actually changing anything.
//!
//! With `--width / --height` it tests a different mode (still
//! CDS_TEST). Pass `--apply` to actually commit the change.

use anyhow::{anyhow, Context, Result};
use clap::Args;

use windows::core::PCWSTR;
use windows::Win32::Graphics::Gdi::{
    ChangeDisplaySettingsW, EnumDisplaySettingsW, CDS_TEST, CDS_TYPE, DEVMODEW,
    DISP_CHANGE_BADDUALVIEW, DISP_CHANGE_BADFLAGS, DISP_CHANGE_BADMODE, DISP_CHANGE_BADPARAM,
    DISP_CHANGE_FAILED, DISP_CHANGE_NOTUPDATED, DISP_CHANGE_RESTART, DISP_CHANGE_SUCCESSFUL,
    DM_BITSPERPEL, DM_DISPLAYFREQUENCY, DM_PELSHEIGHT, DM_PELSWIDTH, ENUM_CURRENT_SETTINGS,
};

#[derive(Args, Debug)]
pub struct DisplaySettingsArgs {
    /// Target width (pixels). Defaults to the current mode's width.
    #[arg(long)]
    pub width: Option<u32>,

    /// Target height (pixels). Defaults to the current mode's height.
    #[arg(long)]
    pub height: Option<u32>,

    /// Target refresh rate (Hz). Defaults to the current mode's rate.
    #[arg(long)]
    pub refresh: Option<u32>,

    /// Color depth in bits per pixel. Defaults to the current mode's
    /// depth.
    #[arg(long)]
    pub bpp: Option<u32>,

    /// Actually apply the mode (CDS_TYPE(0)) instead of CDS_TEST.
    /// Destructive — only use if you know what you're doing.
    #[arg(long, default_value_t = false)]
    pub apply: bool,
}

fn current_mode() -> Result<DEVMODEW> {
    let mut dm = DEVMODEW {
        dmSize: std::mem::size_of::<DEVMODEW>() as u16,
        ..Default::default()
    };
    let ok = unsafe {
        EnumDisplaySettingsW(PCWSTR::null(), ENUM_CURRENT_SETTINGS, &mut dm).as_bool()
    };
    if !ok {
        return Err(anyhow!(
            "EnumDisplaySettingsW(ENUM_CURRENT_SETTINGS) failed"
        ));
    }
    Ok(dm)
}

fn disp_change_label(code: i32) -> &'static str {
    match code {
        x if x == DISP_CHANGE_SUCCESSFUL.0 => "DISP_CHANGE_SUCCESSFUL",
        x if x == DISP_CHANGE_RESTART.0 => "DISP_CHANGE_RESTART",
        x if x == DISP_CHANGE_FAILED.0 => "DISP_CHANGE_FAILED",
        x if x == DISP_CHANGE_BADMODE.0 => "DISP_CHANGE_BADMODE",
        x if x == DISP_CHANGE_NOTUPDATED.0 => "DISP_CHANGE_NOTUPDATED",
        x if x == DISP_CHANGE_BADFLAGS.0 => "DISP_CHANGE_BADFLAGS",
        x if x == DISP_CHANGE_BADPARAM.0 => "DISP_CHANGE_BADPARAM",
        x if x == DISP_CHANGE_BADDUALVIEW.0 => "DISP_CHANGE_BADDUALVIEW",
        _ => "UNKNOWN",
    }
}

pub fn run(args: DisplaySettingsArgs) -> Result<()> {
    let DisplaySettingsArgs {
        width,
        height,
        refresh,
        bpp,
        apply,
    } = args;

    let cur = current_mode().context("reading current display mode")?;
    eprintln!(
        "[info] current mode: {}x{} @ {}Hz, {} bpp",
        cur.dmPelsWidth, cur.dmPelsHeight, cur.dmDisplayFrequency, cur.dmBitsPerPel
    );

    let mut dm = cur;
    // dmFields tells the driver which fields are meaningful in this
    // DEVMODE. Anything we plan to set has to be flagged here.
    dm.dmFields = DM_PELSWIDTH | DM_PELSHEIGHT | DM_DISPLAYFREQUENCY | DM_BITSPERPEL;
    if let Some(w) = width {
        dm.dmPelsWidth = w;
    }
    if let Some(h) = height {
        dm.dmPelsHeight = h;
    }
    if let Some(r) = refresh {
        dm.dmDisplayFrequency = r;
    }
    if let Some(b) = bpp {
        dm.dmBitsPerPel = b;
    }

    let flags = if apply { CDS_TYPE(0) } else { CDS_TEST };
    eprintln!(
        "[step] ChangeDisplaySettingsW({}x{} @ {}Hz, {} bpp, {})",
        dm.dmPelsWidth,
        dm.dmPelsHeight,
        dm.dmDisplayFrequency,
        dm.dmBitsPerPel,
        if apply { "APPLY" } else { "CDS_TEST" }
    );

    let result = unsafe { ChangeDisplaySettingsW(Some(&dm), flags) };
    let label = disp_change_label(result.0);
    eprintln!("[info] ChangeDisplaySettingsW returned {} ({})", result.0, label);

    if result == DISP_CHANGE_SUCCESSFUL {
        println!("{label}");
        Ok(())
    } else {
        Err(anyhow!(
            "ChangeDisplaySettingsW failed: {} ({})",
            result.0,
            label
        ))
    }
}
