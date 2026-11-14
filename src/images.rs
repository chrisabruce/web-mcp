//! Preparing downloaded images for the model.
//!
//! Claude accepts JPEG, PNG, GIF, and WebP and gains nothing from more than ~1568 px on the
//! long edge (larger images are downscaled anyway, costing transfer and tokens). [`prepare`]:
//!
//! * passes small images in a supported format through unchanged,
//! * downscales large ones and re-encodes them (PNG if they have transparency, else JPEG),
//! * converts other raster formats (BMP, ICO) the same way,
//! * returns SVG as text, since it is markup the model can read directly,
//! * rejects HTML (a block page or login wall served instead of the image) and unknown data.
//!
//! This module is pure and synchronous; callers run it on the blocking pool.

use std::io::Cursor;

use image::{DynamicImage, ImageFormat, ImageReader};

/// Longest edge, in pixels, of images sent to the model.
pub const MAX_EDGE: u32 = 1568;

/// Largest image passed through unchanged; bigger files are re-encoded.
const MAX_PASSTHROUGH_BYTES: usize = 3_500_000;

/// Largest SVG returned as text.
const MAX_SVG_CHARS: usize = 100_000;

/// JPEG quality for re-encoded images.
const JPEG_QUALITY: u8 = 85;

/// An image ready to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prepared {
    /// Raster image data.
    Raster(RasterImage),
    /// SVG markup (possibly truncated).
    Svg(String),
}

/// Encoded raster image plus what was done to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RasterImage {
    /// MIME type of `data`.
    pub mime: &'static str,
    /// Encoded bytes.
    pub data: Vec<u8>,
    /// Output dimensions.
    pub width: u32,
    /// Output dimensions.
    pub height: u32,
    /// Original dimensions, if the image was resized.
    pub resized_from: Option<(u32, u32)>,
}

/// Why a response could not be turned into an image.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ImageError {
    /// The server returned a web page instead of an image.
    #[error("the URL returned an HTML page, not an image (often a login wall or block page)")]
    Html,
    /// The bytes are not a recognised image format.
    #[error("the URL did not return a supported image (content-type: {0})")]
    Unsupported(String),
    /// The image could not be decoded or re-encoded.
    #[error("could not process image: {0}")]
    Decode(String),
}

/// Prepares `bytes` (served with `content_type`, if known) for the model.
pub fn prepare(bytes: &[u8], content_type: Option<&str>) -> Result<Prepared, ImageError> {
    let content_type = content_type.unwrap_or("").to_ascii_lowercase();
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]).to_ascii_lowercase();
    let head = head.trim_start_matches('\u{feff}').trim_start();

    if content_type.contains("svg")
        || head.starts_with("<svg")
        || (head.starts_with("<?xml") && head.contains("<svg"))
    {
        let text = String::from_utf8_lossy(bytes);
        return Ok(Prepared::Svg(text.chars().take(MAX_SVG_CHARS).collect()));
    }
    if content_type.contains("html")
        || head.starts_with("<!doctype html")
        || head.starts_with("<html")
    {
        return Err(ImageError::Html);
    }

    let reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| ImageError::Decode(e.to_string()))?;
    let Some(format) = reader.format() else {
        return Err(ImageError::Unsupported(if content_type.is_empty() {
            "unknown".into()
        } else {
            content_type
        }));
    };
    let (width, height) = reader
        .into_dimensions()
        .map_err(|e| ImageError::Decode(e.to_string()))?;

    if let Some(mime) = passthrough_mime(format)
        && width.max(height) <= MAX_EDGE
        && bytes.len() <= MAX_PASSTHROUGH_BYTES
    {
        return Ok(Prepared::Raster(RasterImage {
            mime,
            data: bytes.to_vec(),
            width,
            height,
            resized_from: None,
        }));
    }

    let image = image::load_from_memory_with_format(bytes, format)
        .map_err(|e| ImageError::Decode(e.to_string()))?;
    let resized = if width.max(height) > MAX_EDGE {
        // `thumbnail` is a fast area-averaging downscaler: far quicker than Lanczos on
        // multi-megapixel photos, with comparable quality at these reduction ratios.
        image.thumbnail(MAX_EDGE, MAX_EDGE)
    } else {
        image
    };
    let raster = encode(&resized)?;
    Ok(Prepared::Raster(RasterImage {
        resized_from: (raster.width, raster.height)
            .ne(&(width, height))
            .then_some((width, height)),
        ..raster
    }))
}

/// Formats the model accepts as-is.
fn passthrough_mime(format: ImageFormat) -> Option<&'static str> {
    match format {
        ImageFormat::Jpeg => Some("image/jpeg"),
        ImageFormat::Png => Some("image/png"),
        ImageFormat::Gif => Some("image/gif"),
        ImageFormat::WebP => Some("image/webp"),
        _ => None,
    }
}

/// Encodes as PNG when transparency matters, else as JPEG.
fn encode(image: &DynamicImage) -> Result<RasterImage, ImageError> {
    let mut data = Cursor::new(Vec::new());
    let mime = if image.color().has_alpha() {
        image
            .write_to(&mut data, ImageFormat::Png)
            .map_err(|e| ImageError::Decode(e.to_string()))?;
        "image/png"
    } else {
        let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut data, JPEG_QUALITY);
        image
            .to_rgb8()
            .write_with_encoder(encoder)
            .map_err(|e| ImageError::Decode(e.to_string()))?;
        "image/jpeg"
    };
    Ok(RasterImage {
        mime,
        data: data.into_inner(),
        width: image.width(),
        height: image.height(),
        resized_from: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{Rgb, RgbImage, Rgba, RgbaImage};

    fn encode_as(image: DynamicImage, format: ImageFormat) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        image.write_to(&mut out, format).unwrap();
        out.into_inner()
    }

    fn raster(prepared: Prepared) -> RasterImage {
        match prepared {
            Prepared::Raster(r) => r,
            Prepared::Svg(_) => panic!("expected raster"),
        }
    }

    #[test]
    fn small_supported_images_pass_through() {
        let png = encode_as(
            RgbImage::from_pixel(10, 20, Rgb([1, 2, 3])).into(),
            ImageFormat::Png,
        );
        let out = raster(prepare(&png, Some("image/png")).unwrap());
        assert_eq!(
            (out.mime, out.width, out.height, out.resized_from),
            ("image/png", 10, 20, None)
        );
        assert_eq!(out.data, png);
    }

    #[test]
    fn large_images_are_downscaled_preserving_aspect() {
        let png = encode_as(
            RgbImage::from_pixel(3200, 1600, Rgb([9, 9, 9])).into(),
            ImageFormat::Png,
        );
        let out = raster(prepare(&png, None).unwrap());
        assert_eq!(
            (out.mime, out.width, out.height),
            ("image/jpeg", MAX_EDGE, MAX_EDGE / 2)
        );
        assert_eq!(out.resized_from, Some((3200, 1600)));
    }

    #[test]
    fn unsupported_formats_are_converted_keeping_alpha() {
        let bmp = encode_as(
            RgbaImage::from_pixel(4, 4, Rgba([0, 0, 0, 128])).into(),
            ImageFormat::Bmp,
        );
        let out = raster(prepare(&bmp, Some("image/bmp")).unwrap());
        assert_eq!((out.mime, out.width), ("image/png", 4));
    }

    #[test]
    fn svg_is_returned_as_text_and_html_is_rejected() {
        let svg = br#"<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><circle r="4"/></svg>"#;
        assert!(
            matches!(prepare(svg, Some("image/svg+xml")), Ok(Prepared::Svg(s)) if s.contains("<circle"))
        );
        assert_eq!(
            prepare(b"<!DOCTYPE html><title>Login</title>", Some("text/html")),
            Err(ImageError::Html)
        );
        assert!(matches!(
            prepare(b"\x00\x01garbage", Some("application/octet-stream")),
            Err(ImageError::Unsupported(_))
        ));
    }
}
