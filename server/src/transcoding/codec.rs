use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InputVideoCodec {
    H264,
    Hevc,
    Av1,
    Vp9,
    Mpeg2,
    Vc1,
    OtherProbed,
}

impl InputVideoCodec {
    pub(crate) fn from_probe(value: Option<&str>) -> Self {
        match value.unwrap_or_default().to_ascii_lowercase().as_str() {
            "h264" | "avc" => Self::H264,
            "hevc" | "h265" => Self::Hevc,
            "av1" => Self::Av1,
            "vp9" => Self::Vp9,
            "mpeg2video" | "mpeg2" => Self::Mpeg2,
            "vc1" => Self::Vc1,
            _ => Self::OtherProbed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OutputVideoCodec {
    H264,
    Hevc,
    Av1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ContainerKind {
    MatroskaWebm,
    MovMp4,
    MpegTs,
    Avi,
    Ogg,
    Flv,
    Mpeg,
    OtherProbed,
    Unknown,
}

impl ContainerKind {
    pub(crate) fn from_probe(value: Option<&str>) -> Self {
        let value = value.unwrap_or_default().to_ascii_lowercase();
        if value.is_empty() || value == "unknown" || value == "n/a" {
            Self::Unknown
        } else if value
            .split(',')
            .any(|part| matches!(part, "matroska" | "webm"))
        {
            Self::MatroskaWebm
        } else if value
            .split(',')
            .any(|part| matches!(part, "mov" | "mp4" | "m4a" | "3gp" | "3g2" | "mj2"))
        {
            Self::MovMp4
        } else if value
            .split(',')
            .any(|part| matches!(part, "mpegts" | "mpegtsraw"))
        {
            Self::MpegTs
        } else if value == "avi" {
            Self::Avi
        } else if value == "ogg" {
            Self::Ogg
        } else if value == "flv" {
            Self::Flv
        } else if value
            .split(',')
            .any(|part| matches!(part, "mpeg" | "mpegvideo"))
        {
            Self::Mpeg
        } else {
            Self::OtherProbed
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SampleEntry {
    Avc1,
    Avc3,
    Hvc1,
    Hev1,
    Av01,
    Vp09,
    Mp4a,
    OtherProbed,
    Unknown,
}

impl SampleEntry {
    pub(crate) fn from_probe(value: Option<&str>) -> Self {
        match value.unwrap_or_default().to_ascii_lowercase().as_str() {
            "" | "unknown" | "[0][0][0][0]" => Self::Unknown,
            "avc1" => Self::Avc1,
            "avc3" => Self::Avc3,
            "hvc1" => Self::Hvc1,
            "hev1" => Self::Hev1,
            "av01" => Self::Av01,
            "vp09" => Self::Vp09,
            "mp4a" => Self::Mp4a,
            _ => Self::OtherProbed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VideoProfile {
    H264Baseline,
    H264Main,
    H264High,
    H264High10,
    HevcMain,
    HevcMain10,
    Av1Main,
    Vp9Profile0,
    Vp9Profile2,
    Mpeg2Main,
    Vc1Advanced,
    OtherProbed,
    Unknown,
}

impl VideoProfile {
    pub(crate) fn from_probe(codec: InputVideoCodec, value: Option<&str>) -> Self {
        let normalized = value
            .unwrap_or_default()
            .to_ascii_lowercase()
            .replace([' ', '_', '-'], "");
        if normalized.is_empty() {
            return Self::Unknown;
        }
        match (codec, normalized.as_str()) {
            (InputVideoCodec::H264, "baseline" | "constrainedbaseline") => Self::H264Baseline,
            (InputVideoCodec::H264, "main") => Self::H264Main,
            (InputVideoCodec::H264, "high") => Self::H264High,
            (InputVideoCodec::H264, "high10" | "high10intra") => Self::H264High10,
            (InputVideoCodec::Hevc, "main") => Self::HevcMain,
            (InputVideoCodec::Hevc, "main10") => Self::HevcMain10,
            (InputVideoCodec::Av1, "main") => Self::Av1Main,
            (InputVideoCodec::Vp9, "profile0" | "0") => Self::Vp9Profile0,
            (InputVideoCodec::Vp9, "profile2" | "2") => Self::Vp9Profile2,
            (InputVideoCodec::Mpeg2, "main") => Self::Mpeg2Main,
            (InputVideoCodec::Vc1, "advanced") => Self::Vc1Advanced,
            _ => Self::OtherProbed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PixelFormat {
    Yuv420p,
    Yuv420p10le,
    Yuv422p,
    Yuv422p10le,
    Yuv444p,
    Yuv444p10le,
    Nv12,
    P010le,
    Gray8,
    Gray10le,
    OtherProbed,
    Unknown,
}

impl PixelFormat {
    pub(crate) fn from_probe(value: Option<&str>) -> Self {
        match value.unwrap_or_default().to_ascii_lowercase().as_str() {
            "" | "unknown" | "n/a" => Self::Unknown,
            "yuv420p" => Self::Yuv420p,
            "yuv420p10le" => Self::Yuv420p10le,
            "yuv422p" => Self::Yuv422p,
            "yuv422p10le" => Self::Yuv422p10le,
            "yuv444p" => Self::Yuv444p,
            "yuv444p10le" => Self::Yuv444p10le,
            "nv12" => Self::Nv12,
            "p010le" | "p010" => Self::P010le,
            "gray" | "gray8" => Self::Gray8,
            "gray10le" => Self::Gray10le,
            _ => Self::OtherProbed,
        }
    }

    pub(crate) const fn inferred_bit_depth(self) -> Option<u8> {
        match self {
            Self::Yuv420p | Self::Yuv422p | Self::Yuv444p | Self::Nv12 | Self::Gray8 => Some(8),
            Self::Yuv420p10le
            | Self::Yuv422p10le
            | Self::Yuv444p10le
            | Self::P010le
            | Self::Gray10le => Some(10),
            Self::OtherProbed | Self::Unknown => None,
        }
    }

    pub(crate) const fn chroma(self) -> ChromaSubsampling {
        match self {
            Self::Yuv420p | Self::Yuv420p10le | Self::Nv12 | Self::P010le => {
                ChromaSubsampling::Cs420
            }
            Self::Yuv422p | Self::Yuv422p10le => ChromaSubsampling::Cs422,
            Self::Yuv444p | Self::Yuv444p10le => ChromaSubsampling::Cs444,
            Self::Gray8 | Self::Gray10le => ChromaSubsampling::Monochrome,
            Self::OtherProbed | Self::Unknown => ChromaSubsampling::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChromaSubsampling {
    Cs420,
    Cs422,
    Cs444,
    Monochrome,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FieldOrder {
    Progressive,
    TopFirst,
    BottomFirst,
    Interlaced,
    Unknown,
}

impl FieldOrder {
    pub(crate) fn from_probe(value: Option<&str>) -> Self {
        match value.unwrap_or_default().to_ascii_lowercase().as_str() {
            "progressive" => Self::Progressive,
            "tt" | "tb" | "top" | "top_first" => Self::TopFirst,
            "bb" | "bt" | "bottom" | "bottom_first" => Self::BottomFirst,
            "interlaced" => Self::Interlaced,
            _ => Self::Unknown,
        }
    }
}

macro_rules! probed_color_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase")]
        pub enum $name { $($variant,)+ OtherProbed, Unknown }

        impl $name {
            pub(crate) fn from_probe(value: Option<&str>) -> Self {
                match value.unwrap_or_default().to_ascii_lowercase().as_str() {
                    "" | "unknown" | "reserved" | "n/a" => Self::Unknown,
                    $($value => Self::$variant,)+
                    _ => Self::OtherProbed,
                }
            }
        }
    };
}

probed_color_enum!(ColorPrimaries {
    Bt709 => "bt709",
    Bt2020 => "bt2020",
    Smpte170m => "smpte170m",
    Smpte432 => "smpte432",
});
probed_color_enum!(ColorTransfer {
    Bt709 => "bt709",
    Smpte2084 => "smpte2084",
    AribStdB67 => "arib-std-b67",
    Iec6196621 => "iec61966-2-1",
});
probed_color_enum!(ColorMatrix {
    Bt709 => "bt709",
    Bt2020Nc => "bt2020nc",
    Bt2020C => "bt2020c",
    Smpte170m => "smpte170m",
    Rgb => "gbr",
});

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ColorRange {
    Limited,
    Full,
    OtherProbed,
    Unknown,
}

impl ColorRange {
    pub(crate) fn from_probe(value: Option<&str>) -> Self {
        match value.unwrap_or_default().to_ascii_lowercase().as_str() {
            "tv" | "mpeg" | "limited" => Self::Limited,
            "pc" | "jpeg" | "full" => Self::Full,
            "" | "unknown" | "n/a" => Self::Unknown,
            _ => Self::OtherProbed,
        }
    }
}
