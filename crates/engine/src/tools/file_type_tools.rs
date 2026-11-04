//! Detects a file's type from its magic bytes (file signature), without parsing the full file.
//! Target-free: works on any file path or the active target.

use super::static_input::{self, PrefixInput};
use crate::tool::{Ctx, Effects, Requires, ToolOutput, ToolSpec, Toolset, parse_params, schema_of};
use craft_anything_evidence::{Confidence, Coverage, EvidenceBuilder, Limitation, Location, Subject, ToolError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// A known file signature: offset, bytes to match, and the type name.
#[derive(Debug, Clone)]
struct Signature {
    offset: usize,
    bytes: &'static [u8],
    file_type: &'static str,
    mime: &'static str,
    confidence: Confidence,
}

/// All known signatures, ordered so more specific/longer matches win.
const SIGNATURES: &[Signature] = &[
    // Images
    Signature { offset: 0, bytes: b"\x89PNG\r\n\x1a\n", file_type: "PNG image", mime: "image/png", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\xff\xd8\xff", file_type: "JPEG image", mime: "image/jpeg", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"GIF87a", file_type: "GIF image", mime: "image/gif", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"GIF89a", file_type: "GIF image", mime: "image/gif", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"BM", file_type: "BMP image", mime: "image/bmp", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\x00\x00\x01\x00", file_type: "ICO image", mime: "image/x-icon", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\x00\x00\x02\x00", file_type: "CUR image", mime: "image/x-icon", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"II\x2a\x00", file_type: "TIFF image (little-endian)", mime: "image/tiff", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"MM\x00\x2a", file_type: "TIFF image (big-endian)", mime: "image/tiff", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\xfd\xfb\x28", file_type: "HEIC image", mime: "image/heic", confidence: Confidence::Derived },

    // Documents
    Signature { offset: 0, bytes: b"%PDF", file_type: "PDF document", mime: "application/pdf", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\x25\x50\x44\x46", file_type: "PDF document", mime: "application/pdf", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", file_type: "Compound file (legacy DOC/XLS/PPT)", mime: "application/msword", confidence: Confidence::Derived },
    Signature { offset: 0, bytes: b"\x7FELF", file_type: "ELF executable", mime: "application/x-executable", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"MZ", file_type: "PE executable (Windows .exe/.dll)", mime: "application/x-dosexec", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\xCA\xFE\xBA\xBE", file_type: "Mach-O universal binary / Java class", mime: "application/x-mach-binary", confidence: Confidence::Derived },
    Signature { offset: 0, bytes: b"\xFE\xED\xFA\xCE", file_type: "Mach-O executable (32-bit)", mime: "application/x-mach-binary", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\xFE\xED\xFA\xCF", file_type: "Mach-O executable (64-bit)", mime: "application/x-mach-binary", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\xCF\xFA\xED\xFE", file_type: "Mach-O executable (32-bit, big-endian)", mime: "application/x-mach-binary", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\xCF\xFA\xED\xFF", file_type: "Mach-O executable (64-bit, big-endian)", mime: "application/x-mach-binary", confidence: Confidence::Observed },

    // Archives
    Signature { offset: 0, bytes: b"\x1F\x8B\x08", file_type: "GZIP archive", mime: "application/gzip", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"BZh", file_type: "BZIP2 archive", mime: "application/x-bzip2", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\xFD\x7F\x5A\x58\x5A", file_type: "XZ archive", mime: "application/x-xz", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\x28\xB5\x2F\xFD", file_type: "Zstandard archive", mime: "application/zstd", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\x37\x7A\xBC\xAF\x27\x1C", file_type: "7-Zip archive", mime: "application/x-7z-compressed", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"Rar!\x1A\x07", file_type: "RAR archive", mime: "application/x-rar-compressed", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\x52\x61\x72\x21\x1A\x07\x00", file_type: "RAR5 archive", mime: "application/x-rar-compressed", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\x04\x22\x4D\x18", file_type: "LZ4 archive", mime: "application/x-lz4", confidence: Confidence::Derived },

    // Audio
    Signature { offset: 0, bytes: b"ID3", file_type: "MP3 audio", mime: "audio/mpeg", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\xFF\xFB", file_type: "MP3 audio", mime: "audio/mpeg", confidence: Confidence::Derived },
    Signature { offset: 0, bytes: b"\xFF\xF3", file_type: "MP3 audio", mime: "audio/mpeg", confidence: Confidence::Derived },
    Signature { offset: 0, bytes: b"\xFF\xF2", file_type: "MP3 audio", mime: "audio/mpeg", confidence: Confidence::Derived },
    Signature { offset: 0, bytes: b"\x42\x4F\x4F\x53", file_type: "Ogg media", mime: "application/ogg", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"fLaC", file_type: "FLAC audio", mime: "audio/flac", confidence: Confidence::Observed },

    // Video
    Signature { offset: 0, bytes: b"\x00\x00\x00\x18\x66\x74\x79\x70", file_type: "ISO base media (ftyp)", mime: "application/octet-stream", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\x00\x00\x00\x20\x66\x74\x79\x70", file_type: "ISO base media (ftyp)", mime: "application/octet-stream", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\x00\x00\x00\x24\x66\x74\x79\x70", file_type: "ISO base media (ftyp)", mime: "application/octet-stream", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\x00\x00\x00\x1C\x66\x74\x79\x70\x6D\x70\x34\x32", file_type: "ISO base media (ftyp)", mime: "application/octet-stream", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\x1A\x45\xDF\xA3", file_type: "Matroska video (MKV/WebM)", mime: "video/x-matroska", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\x4D\x54\x68\x64", file_type: "MIDI file", mime: "audio/midi", confidence: Confidence::Observed },

    // Executables and code
    Signature { offset: 0, bytes: b"\x7FELF", file_type: "ELF executable", mime: "application/x-executable", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"MZ", file_type: "PE executable (Windows .exe/.dll/.sys)", mime: "application/x-dosexec", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\xCA\xFE\xBA\xBE", file_type: "Java class file", mime: "application/java-vm", confidence: Confidence::Derived },
    Signature { offset: 0, bytes: b"PK\x03\x04", file_type: "ZIP archive (or DOCX/XLSX/PPTX/ODT/etc.)", mime: "application/java-archive", confidence: Confidence::Derived },
    Signature { offset: 0, bytes: b"\x7F\x45\x4C\x46", file_type: "ELF shared object", mime: "application/x-sharedlib", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"\x00\x61\x73\x6D", file_type: "WebAssembly module", mime: "application/wasm", confidence: Confidence::Observed },

    // Text / script
    Signature { offset: 0, bytes: b"#!/", file_type: "Shell script", mime: "text/x-shellscript", confidence: Confidence::Observed },
    Signature { offset: 0, bytes: b"<?xml", file_type: "XML document", mime: "application/xml", confidence: Confidence::Observed },
]

/// Detect file type from first bytes.
fn detect(data: &[u8]) -> Option<(String, String, Confidence)> {
    for sig in SIGNATURES {
        if sig.offset + sig.bytes.len() <= data.len() {
            if data[sig.offset..sig.offset + sig.bytes.len()] == sig.bytes[..] {
                return Some((sig.file_type.to_string(), sig.mime.to_string(), sig.confidence));
            }
        }
    }
    None
}

/// Classify a RIFF container by reading the format identifier at byte offset 8.
fn classify_riff(data: &[u8]) -> Option<(String, String, Confidence)> {
    if data.len() < 12 {
        return None;
    }
    if &data[0..4] != b"RIFF" {
        return None;
    }
    let form_type = &data[8..12];
    match form_type {
        b"WEBP" => Some(("WEBP image".to_string(), "image/webp".to_string(), Confidence::Observed)),
        b"WAVE" => Some(("WAV audio".to_string(), "audio/wav".to_string(), Confidence::Observed)),
        b"AVI " => Some(("AVI video".to_string(), "video/x-msvideo".to_string(), Confidence::Observed)),
        _ => Some(("RIFF container".to_string(), "application/riff".to_string(), Confidence::Derived)),
    }
}

/// Is the data printable text (ASCII or valid UTF-8)?
///
/// `whole` tells whether `data` covers the entire file or just a sampled prefix.
/// When `whole` is false and the sample ends mid-UTF-8-sequence, the truncation
/// is tolerated because more bytes may follow. When `whole` is true, truncation
/// and malformed bytes are rejected.
fn looks_like_text(data: &[u8], whole: bool) -> bool {
    if data.is_empty() {
        return false;
    }
    let sample = data.len().min(4096);
    let mut valid_utf8 = 0usize;
    let mut i = 0;
    while i < sample {
        let b = data[i];
        // Allow tab, newline, carriage return, and printable ASCII
        if b == 0x09 || b == 0x0A || b == 0x0D || (0x20..=0x7E).contains(&b) {
            valid_utf8 += 1;
            i += 1;
        } else if (0xC2..=0xDF).contains(&b) {
            // 2-byte UTF-8: U+0080 to U+07FF
            if i + 1 < sample && (0x80..=0xBF).contains(&data[i + 1]) {
                valid_utf8 += 2;
                i += 2;
            } else if !whole && i + 1 == sample {
                // Truncated at end of incomplete file: tolerate, more bytes may follow
                valid_utf8 += 1;
                i += 1;
            } else {
                return false;
            }
        } else if (0xE0..=0xEF).contains(&b) {
            // 3-byte UTF-8: U+0800 to U+FFFF, with scalar range restrictions
            if i + 3 <= sample {
                let b2 = data[i + 1];
                let b3 = data[i + 2];
                let valid = match b {
                    0xE0 => (0xA0..=0xBF).contains(&b2) && (0x80..=0xBF).contains(&b3),
                    0xED => (0x80..=0x9F).contains(&b2) && (0x80..=0xBF).contains(&b3),
                    _ => (0x80..=0xBF).contains(&b2) && (0x80..=0xBF).contains(&b3),
                };
                if valid {
                    valid_utf8 += 3;
                    i += 3;
                } else {
                    return false;
                }
            } else if !whole {
                // Truncated at end of incomplete file: tolerate
                valid_utf8 += sample - i;
                i = sample;
            } else {
                return false;
            }
        } else if (0xF0..=0xF4).contains(&b) {
            // 4-byte UTF-8: U+10000 to U+10FFFF, with scalar range restrictions
            if i + 4 <= sample {
                let b2 = data[i + 1];
                let b3 = data[i + 2];
                let b4 = data[i + 3];
                let valid = match b {
                    0xF0 => (0x90..=0xBF).contains(&b2) && (0x80..=0xBF).contains(&b3) && (0x80..=0xBF).contains(&b4),
                    0xF4 => (0x80..=0x8F).contains(&b2) && (0x80..=0xBF).contains(&b3) && (0x80..=0xBF).contains(&b4),
                    _ => (0x80..=0xBF).contains(&b2) && (0x80..=0xBF).contains(&b3) && (0x80..=0xBF).contains(&b4),
                };
                if valid {
                    valid_utf8 += 4;
                    i += 4;
                } else {
                    return false;
                }
            } else if !whole {
                // Truncated at end of incomplete file: tolerate
                valid_utf8 += sample - i;
                i = sample;
            } else {
                return false;
            }
        } else {
            // Invalid byte: control characters or non-UTF-8 leading bytes
            return false;
        }
    }
    valid_utf8 as f64 / sample as f64 > 0.85
}

pub fn specs() -> Vec<ToolSpec> {
    let e = Effects::EVIDENCE;
    vec![
        spec(
            "file_type_detect",
            "File type detector",
            "Inspects a file's first bytes (magic bytes / file signature) and reports the likely file type and MIME type, with confidence. No parsing, no execution—safe on any file.",
            "Tell me what kind of file this is, from its signature.",
            Toolset::Formats,
            e,
            Requires::Nothing,
            schema_of::<DetectParams>,
            file_type_detect,
        ),
    ]
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetectParams {
    /// Absolute path of the file to inspect; the active target when omitted.
    #[serde(default)]
    pub path: Option<String>,
}

fn file_type_detect(ctx: &mut Ctx<'_>, params: Value) -> Result<ToolOutput, ToolError> {
    let p: DetectParams = parse_params(params)?;

    let input: PrefixInput = static_input::load_prefix(ctx, p.path.as_deref(), 4096)?;
    let data = &input.bytes;

    // Check RIFF container first (needs format identifier at offset 8)
    if let Some((file_type, mime, confidence)) = classify_riff(data) {
        let result = json!({
            "file_type": file_type,
            "mime_type": mime,
            "bytes_inspected": data.len(),
            "file_size": input.file_size,
            "whole_file": input.whole,
        });
        let summary = format!("{file_type} ({mime})");
        let subject = input.subject.clone();
        let evidence = EvidenceBuilder::new(
            "file_type_detect",
            subject,
            craft_anything_evidence::Environment::builtin(ctx.session.clean_room()),
        )
        .params(params)
        .result(result.clone())
        .summary(summary)
        .confidence(confidence)
        .coverage(Coverage {
            status: if input.whole {
                craft_anything_evidence::CoverageStatus::Complete
            } else {
                craft_anything_evidence::CoverageStatus::Partial
            },
            examined: Some(data.len() as u64),
            total: Some(input.file_size),
            next_offset: None,
        })
        .limitation(Limitation::new(
            "magic-bytes-only",
            "magic-byte detection only inspects the first few kilobytes; container formats (ZIP, RIFF) may hide inner types",
        ))
        .location(Location::new("file", input.path.display().to_string()))
        .build()?;

        return Ok(ToolOutput::evidence(evidence));
    }

    // Check other signatures
    if let Some((file_type, mime, confidence)) = detect(data) {
        let result = json!({
            "file_type": file_type,
            "mime_type": mime,
            "bytes_inspected": data.len(),
            "file_size": input.file_size,
            "whole_file": input.whole,
        });
        let summary = format!("{file_type} ({mime})");
        let subject = input.subject.clone();
        let evidence = EvidenceBuilder::new(
            "file_type_detect",
            subject,
            craft_anything_evidence::Environment::builtin(ctx.session.clean_room()),
        )
        .params(params)
        .result(result.clone())
        .summary(summary)
        .confidence(confidence)
        .coverage(Coverage {
            status: if input.whole {
                craft_anything_evidence::CoverageStatus::Complete
            } else {
                craft_anything_evidence::CoverageStatus::Partial
            },
            examined: Some(data.len() as u64),
            total: Some(input.file_size),
            next_offset: None,
        })
        .limitation(Limitation::new(
            "magic-bytes-only",
            "magic-byte detection only inspects the first few kilobytes; container formats (ZIP, RIFF) may hide inner types",
        ))
        .location(Location::new("file", input.path.display().to_string()))
        .build()?;

        return Ok(ToolOutput::evidence(evidence));
    }

    // Fallback: text or unknown binary
    if looks_like_text(data, input.whole) {
        let file_type = "Plain text";
        let mime = "text/plain";
        let confidence = Confidence::Derived;
        let result = json!({
            "file_type": file_type,
            "mime_type": mime,
            "bytes_inspected": data.len(),
            "file_size": input.file_size,
            "whole_file": input.whole,
        });
        let summary = format!("{file_type} ({mime})");
        let subject = input.subject.clone();
        let evidence = EvidenceBuilder::new(
            "file_type_detect",
            subject,
            craft_anything_evidence::Environment::builtin(ctx.session.clean_room()),
        )
        .params(params)
        .result(result.clone())
        .summary(summary)
        .confidence(confidence)
        .coverage(Coverage {
            status: if input.whole {
                craft_anything_evidence::CoverageStatus::Complete
            } else {
                craft_anything_evidence::CoverageStatus::Partial
            },
            examined: Some(data.len() as u64),
            total: Some(input.file_size),
            next_offset: None,
        })
        .limitation(Limitation::new(
            "magic-bytes-only",
            "magic-byte detection only inspects the first few kilobytes; container formats (ZIP, RIFF) may hide inner types",
        ))
        .location(Location::new("file", input.path.display().to_string()))
        .build()?;

        return Ok(ToolOutput::evidence(evidence));
    }

    let file_type = "Unknown binary data";
    let mime = "application/octet-stream";
    let confidence = Confidence::Inferred;
    let result = json!({
        "file_type": file_type,
        "mime_type": mime,
        "bytes_inspected": data.len(),
        "file_size": input.file_size,
        "whole_file": input.whole,
    });
    let summary = format!("{file_type} ({mime})");
        let subject = input.subject.clone();
        let evidence = EvidenceBuilder::new(
            "file_type_detect",
            subject,
            craft_anything_evidence::Environment::builtin(ctx.session.clean_room()),
        )
        .params(params)
        .result(result.clone())
        .summary(summary)
        .confidence(confidence)
        .coverage(Coverage {
            status: if input.whole {
                craft_anything_evidence::CoverageStatus::Complete
            } else {
                craft_anything_evidence::CoverageStatus::Partial
            },
            examined: Some(data.len() as u64),
            total: Some(input.file_size),
            next_offset: None,
        })
        .limitation(Limitation::new(
            "magic-bytes-only",
            "magic-byte detection only inspects the first few kilobytes; container formats (ZIP, RIFF) may hide inner types",
        ))
        .location(Location::new("file", input.path.display().to_string()))
        .build()?;

    Ok(ToolOutput::evidence(evidence))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_png() {
        let data = b"\x89PNG\r\n\x1a\nrest of file";
        let hit = detect(data);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().0, "PNG image");
    }

    #[test]
    fn detects_elf() {
        let data = b"\x7FELF\x02\x01\x01";
        let hit = detect(data);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().0, "ELF executable");
    }

    #[test]
    fn detects_zip() {
        let data = b"PK\x03\x04\x14\x00";
        let hit = detect(data);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().0, "ZIP archive (or DOCX/XLSX/PPTX/ODT/etc.)");
    }

    #[test]
    fn detects_ogg() {
        let data = b"OggS\x00\x02\x00\x00";
        let hit = detect(data);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().0, "Ogg media");
    }

    #[test]
    fn unknown_returns_none() {
        let data = b"\x00\x01\x02\x03\x04\x05";
        assert!(detect(data).is_none());
    }

    #[test]
    fn text_detection() {
        let data = b"Hello, world!\nThis is text.";
        assert!(looks_like_text(data, true));
    }

    #[test]
    fn arabic_text_detection() {
        let data = "مرحبا بالعالم".as_bytes();
        assert!(looks_like_text(data, true));
    }

    #[test]
    fn binary_not_text() {
        let data = b"\x00\x01\x02\x03\xFF\xFE\xFD";
        assert!(!looks_like_text(data, true));
    }

    #[test]
    fn riff_classification() {
        // WebP
        let data = b"RIFF\x00\x00\x00\x00WEBPVP8 ";
        let hit = classify_riff(data);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().0, "WEBP image");

        // WAV
        let data = b"RIFF\x00\x00\x00\x00WAVEfmt ";
        let hit = classify_riff(data);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().0, "WAV audio");

        // AVI
        let data = b"RIFF\x00\x00\x00\x00AVI ";
        let hit = classify_riff(data);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().0, "AVI video");
    }

    #[test]
    fn confidence_ordering() {
        assert!(Confidence::Observed > Confidence::Derived);
        assert!(Confidence::Derived > Confidence::Inferred);
        assert!(Confidence::Observed > Confidence::Inferred);
    }
}
