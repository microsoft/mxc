//! GDI-based screenshot via the `win-screenshot` crate (BitBlt /
//! PrintWindow under the hood). Works in any non-AppContainer process
//! without needing the `graphicsCapture` capability.

use anyhow::{anyhow, Context, Result};
use std::path::Path;

use image::RgbaImage;
use win_screenshot::prelude::capture_display;

pub fn capture(out_path: &Path) -> Result<(u32, u32)> {
    let buf = capture_display().map_err(|e| anyhow!("capture_display failed: {e:?}"))?;
    let img = RgbaImage::from_raw(buf.width, buf.height, buf.pixels)
        .ok_or_else(|| anyhow!("failed to construct image buffer"))?;
    img.save(out_path)
        .with_context(|| format!("failed to write {}", out_path.display()))?;
    Ok((buf.width, buf.height))
}
