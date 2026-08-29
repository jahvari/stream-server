use super::{
    codec::{
        ChromaSubsampling, ColorMatrix, ColorPrimaries, ColorRange, ColorTransfer, ContainerKind,
        FieldOrder, InputVideoCodec, PixelFormat, SampleEntry, VideoProfile,
    },
    model::{FrameRateClass, MediaDescriptor, RationalRate},
    process::{ProcessErrorCode, StdoutPolicy},
    runtime::{RuntimeCommand, RuntimeCommandError, RuntimeExecutable, TranscodingService},
    source::{SourceActivitySnapshot, SourceError, ValidatedMediaSource},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    ffi::OsString,
    fmt,
    num::NonZeroU32,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::Notify, time::Instant};
use tokio_util::sync::CancellationToken;

pub const MAX_PROBE_STDOUT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PROBE_STDERR_BYTES: usize = 1024 * 1024;
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_NODES: usize = 65_536;
const MAX_JSON_STRING_BYTES: usize = 4_096;
const MAX_STREAMS: usize = 128;
const MAX_CHAPTERS: usize = 2_048;
const MAX_SIDE_DATA_PER_STREAM: usize = 64;
const PROBE_INACTIVITY: Duration = Duration::from_secs(30);
const PROBE_STARVATION_DEFAULT: Duration = Duration::from_secs(10 * 60);
const PROBE_HARD_DEADLINE: Duration = Duration::from_secs(30 * 60);
const CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const CACHE_MAX_ENTRIES: usize = 128;
const CACHE_MAX_WEIGHT: usize = 16 * 1024 * 1024;
const CACHE_MAX_IN_FLIGHT: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeErrorCode {
    OutputTooLarge,
    MalformedOutput,
    LimitExceeded,
    RuntimeUnavailable,
    SourceInvalid,
    ProcessFailure,
    NonZeroExit,
    Inactivity,
    SourceStarvation,
    OverallDeadline,
    CapacityExceeded,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeError {
    code: ProbeErrorCode,
}

impl ProbeError {
    const fn new(code: ProbeErrorCode) -> Self {
        Self { code }
    }

    pub const fn code(&self) -> ProbeErrorCode {
        self.code
    }
}

impl fmt::Display for ProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            ProbeErrorCode::OutputTooLarge => "probe output exceeded its byte limit",
            ProbeErrorCode::MalformedOutput => "probe output was malformed",
            ProbeErrorCode::LimitExceeded => "probe metadata exceeded a structural limit",
            ProbeErrorCode::RuntimeUnavailable => "paired media runtime is unavailable",
            ProbeErrorCode::SourceInvalid => "validated media source is no longer usable",
            ProbeErrorCode::ProcessFailure => "media probe process failed",
            ProbeErrorCode::NonZeroExit => "media probe exited unsuccessfully",
            ProbeErrorCode::Inactivity => "media probe made no source progress",
            ProbeErrorCode::SourceStarvation => "media probe source remained unavailable",
            ProbeErrorCode::OverallDeadline => "media probe exceeded its hard overall deadline",
            ProbeErrorCode::CapacityExceeded => "media probe admission capacity is exhausted",
            ProbeErrorCode::Cancelled => "media probe was cancelled",
        })
    }
}

impl std::error::Error for ProbeError {}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(transparent)]
pub struct SafeProbeText(String);

impl SafeProbeText {
    fn parse(value: Option<&str>, fallback: &'static str) -> Result<Self, ProbeError> {
        let value = value.filter(|value| !value.is_empty()).unwrap_or(fallback);
        if value.len() > 256 || value.chars().any(char::is_control) {
            return Err(ProbeError::new(ProbeErrorCode::LimitExceeded));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeRational {
    numerator: i64,
    denominator: u64,
}

impl ProbeRational {
    pub fn numerator(self) -> i64 {
        self.numerator
    }

    pub fn denominator(self) -> u64 {
        self.denominator
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamDisposition {
    pub default: bool,
    pub forced: bool,
    pub hearing_impaired: bool,
    pub visual_impaired: bool,
    pub attached_picture: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ColorDescriptor {
    pub primaries: ColorPrimaries,
    pub transfer: ColorTransfer,
    pub matrix: ColorMatrix,
    pub range: ColorRange,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MasteringDisplayMetadata {
    pub red_x: Option<ProbeRational>,
    pub red_y: Option<ProbeRational>,
    pub green_x: Option<ProbeRational>,
    pub green_y: Option<ProbeRational>,
    pub blue_x: Option<ProbeRational>,
    pub blue_y: Option<ProbeRational>,
    pub white_point_x: Option<ProbeRational>,
    pub white_point_y: Option<ProbeRational>,
    pub min_luminance: Option<ProbeRational>,
    pub max_luminance: Option<ProbeRational>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentLightMetadata {
    pub max_content: Option<u32>,
    pub max_average: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DolbyVisionMetadata {
    pub profile: Option<u8>,
    pub level: Option<u8>,
    pub rpu_present: Option<bool>,
    pub enhancement_layer_present: Option<bool>,
    pub base_layer_present: Option<bool>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HdrMetadata {
    mastering_display: Option<MasteringDisplayMetadata>,
    content_light: Option<ContentLightMetadata>,
    dolby_vision: Option<DolbyVisionMetadata>,
}

impl HdrMetadata {
    pub fn mastering_display(&self) -> Option<&MasteringDisplayMetadata> {
        self.mastering_display.as_ref()
    }

    pub fn content_light(&self) -> Option<ContentLightMetadata> {
        self.content_light
    }

    pub fn dolby_vision(&self) -> Option<DolbyVisionMetadata> {
        self.dolby_vision
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoStreamDescriptor {
    index: u32,
    codec: InputVideoCodec,
    codec_display: SafeProbeText,
    sample_entry: SampleEntry,
    codec_tag: Option<SafeProbeText>,
    profile: VideoProfile,
    profile_display: Option<SafeProbeText>,
    level: Option<u32>,
    start_micros: Option<i64>,
    duration_micros: Option<u64>,
    width: Option<u32>,
    height: Option<u32>,
    sample_aspect_ratio: Option<ProbeRational>,
    display_aspect_ratio: Option<ProbeRational>,
    pixel_format: PixelFormat,
    pixel_format_display: Option<SafeProbeText>,
    bit_depth: Option<u8>,
    chroma: ChromaSubsampling,
    nominal_frame_rate: Option<RationalRate>,
    average_frame_rate: Option<RationalRate>,
    frame_rate_class: FrameRateClass,
    stream_time_base: Option<ProbeRational>,
    codec_time_base: Option<ProbeRational>,
    field_order: FieldOrder,
    rotation_degrees: Option<i16>,
    color: ColorDescriptor,
    hdr: HdrMetadata,
    bitrate: Option<u64>,
    language: Option<SafeProbeText>,
    disposition: StreamDisposition,
}

impl VideoStreamDescriptor {
    pub fn index(&self) -> u32 {
        self.index
    }
    pub fn codec(&self) -> InputVideoCodec {
        self.codec
    }
    pub fn codec_display(&self) -> &str {
        self.codec_display.as_str()
    }
    pub fn sample_entry(&self) -> SampleEntry {
        self.sample_entry
    }
    pub fn codec_tag(&self) -> Option<&str> {
        self.codec_tag.as_ref().map(SafeProbeText::as_str)
    }
    pub fn profile(&self) -> VideoProfile {
        self.profile
    }
    pub fn profile_display(&self) -> Option<&str> {
        self.profile_display.as_ref().map(SafeProbeText::as_str)
    }
    pub fn level(&self) -> Option<u32> {
        self.level
    }
    pub fn pixel_format(&self) -> PixelFormat {
        self.pixel_format
    }
    pub fn pixel_format_display(&self) -> Option<&str> {
        self.pixel_format_display
            .as_ref()
            .map(SafeProbeText::as_str)
    }
    pub fn bit_depth(&self) -> Option<u8> {
        self.bit_depth
    }
    pub fn chroma(&self) -> ChromaSubsampling {
        self.chroma
    }
    pub fn sample_aspect_ratio(&self) -> Option<ProbeRational> {
        self.sample_aspect_ratio
    }
    pub fn display_aspect_ratio(&self) -> Option<ProbeRational> {
        self.display_aspect_ratio
    }
    pub fn nominal_frame_rate(&self) -> Option<RationalRate> {
        self.nominal_frame_rate
    }
    pub fn average_frame_rate(&self) -> Option<RationalRate> {
        self.average_frame_rate
    }
    pub fn frame_rate_class(&self) -> FrameRateClass {
        self.frame_rate_class
    }
    pub fn stream_time_base(&self) -> Option<ProbeRational> {
        self.stream_time_base
    }
    pub fn codec_time_base(&self) -> Option<ProbeRational> {
        self.codec_time_base
    }
    pub fn field_order(&self) -> FieldOrder {
        self.field_order
    }
    pub fn color(&self) -> ColorDescriptor {
        self.color
    }
    pub fn rotation_degrees(&self) -> Option<i16> {
        self.rotation_degrees
    }
    pub fn hdr(&self) -> &HdrMetadata {
        &self.hdr
    }
    pub fn width(&self) -> Option<u32> {
        self.width
    }
    pub fn height(&self) -> Option<u32> {
        self.height
    }
    pub fn bitrate(&self) -> Option<u64> {
        self.bitrate
    }
    pub fn start_micros(&self) -> Option<i64> {
        self.start_micros
    }
    pub fn duration_micros(&self) -> Option<u64> {
        self.duration_micros
    }
    pub fn language(&self) -> Option<&str> {
        self.language.as_ref().map(SafeProbeText::as_str)
    }
    pub fn disposition(&self) -> StreamDisposition {
        self.disposition
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AudioStreamDescriptor {
    index: u32,
    codec_display: SafeProbeText,
    codec_tag: Option<SafeProbeText>,
    profile_display: Option<SafeProbeText>,
    start_micros: Option<i64>,
    duration_micros: Option<u64>,
    stream_time_base: Option<ProbeRational>,
    sample_rate: Option<u32>,
    channels: Option<u16>,
    channel_layout: Option<SafeProbeText>,
    bitrate: Option<u64>,
    language: Option<SafeProbeText>,
    disposition: StreamDisposition,
}

impl AudioStreamDescriptor {
    pub fn index(&self) -> u32 {
        self.index
    }
    pub fn codec_display(&self) -> &str {
        self.codec_display.as_str()
    }
    pub fn codec_tag(&self) -> Option<&str> {
        self.codec_tag.as_ref().map(SafeProbeText::as_str)
    }
    pub fn profile_display(&self) -> Option<&str> {
        self.profile_display.as_ref().map(SafeProbeText::as_str)
    }
    pub fn start_micros(&self) -> Option<i64> {
        self.start_micros
    }
    pub fn duration_micros(&self) -> Option<u64> {
        self.duration_micros
    }
    pub fn stream_time_base(&self) -> Option<ProbeRational> {
        self.stream_time_base
    }
    pub fn sample_rate(&self) -> Option<u32> {
        self.sample_rate
    }
    pub fn channels(&self) -> Option<u16> {
        self.channels
    }
    pub fn channel_layout(&self) -> Option<&str> {
        self.channel_layout.as_ref().map(SafeProbeText::as_str)
    }
    pub fn bitrate(&self) -> Option<u64> {
        self.bitrate
    }
    pub fn language(&self) -> Option<&str> {
        self.language.as_ref().map(SafeProbeText::as_str)
    }
    pub fn disposition(&self) -> StreamDisposition {
        self.disposition
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubtitleStreamDescriptor {
    index: u32,
    codec_display: SafeProbeText,
    codec_tag: Option<SafeProbeText>,
    start_micros: Option<i64>,
    duration_micros: Option<u64>,
    stream_time_base: Option<ProbeRational>,
    language: Option<SafeProbeText>,
    disposition: StreamDisposition,
}

impl SubtitleStreamDescriptor {
    pub fn index(&self) -> u32 {
        self.index
    }
    pub fn codec_display(&self) -> &str {
        self.codec_display.as_str()
    }
    pub fn codec_tag(&self) -> Option<&str> {
        self.codec_tag.as_ref().map(SafeProbeText::as_str)
    }
    pub fn start_micros(&self) -> Option<i64> {
        self.start_micros
    }
    pub fn duration_micros(&self) -> Option<u64> {
        self.duration_micros
    }
    pub fn stream_time_base(&self) -> Option<ProbeRational> {
        self.stream_time_base
    }
    pub fn language(&self) -> Option<&str> {
        self.language.as_ref().map(SafeProbeText::as_str)
    }
    pub fn disposition(&self) -> StreamDisposition {
        self.disposition
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MediaStreamDescriptor {
    Video(Box<VideoStreamDescriptor>),
    Audio(AudioStreamDescriptor),
    Subtitle(SubtitleStreamDescriptor),
    Other {
        index: u32,
        track_display: SafeProbeText,
        codec_display: SafeProbeText,
        codec_tag: Option<SafeProbeText>,
        start_micros: Option<i64>,
        duration_micros: Option<u64>,
        stream_time_base: Option<ProbeRational>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChapterDescriptor {
    id: i64,
    start_micros: Option<i64>,
    end_micros: Option<i64>,
    title: Option<SafeProbeText>,
}

impl ChapterDescriptor {
    pub fn id(&self) -> i64 {
        self.id
    }
    pub fn start_micros(&self) -> Option<i64> {
        self.start_micros
    }
    pub fn end_micros(&self) -> Option<i64> {
        self.end_micros
    }
    pub fn title(&self) -> Option<&str> {
        self.title.as_ref().map(SafeProbeText::as_str)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeDocument {
    container: ContainerKind,
    container_display: SafeProbeText,
    start_micros: Option<i64>,
    duration_micros: Option<u64>,
    bitrate: Option<u64>,
    streams: Vec<MediaStreamDescriptor>,
    chapters: Vec<ChapterDescriptor>,
    selected_video_stream: Option<u32>,
    selected_audio_stream: Option<u32>,
}

impl ProbeDocument {
    pub fn container(&self) -> ContainerKind {
        self.container
    }
    pub fn container_display(&self) -> &str {
        self.container_display.as_str()
    }
    pub fn start_micros(&self) -> Option<i64> {
        self.start_micros
    }
    pub fn duration_micros(&self) -> Option<u64> {
        self.duration_micros
    }
    pub fn bitrate(&self) -> Option<u64> {
        self.bitrate
    }
    pub fn streams(&self) -> &[MediaStreamDescriptor] {
        &self.streams
    }
    pub fn chapters(&self) -> &[ChapterDescriptor] {
        &self.chapters
    }
    pub fn selected_video_stream(&self) -> Option<u32> {
        self.selected_video_stream
    }
    pub fn selected_audio_stream(&self) -> Option<u32> {
        self.selected_audio_stream
    }

    pub fn video_streams(&self) -> impl Iterator<Item = &VideoStreamDescriptor> {
        self.streams.iter().filter_map(|stream| match stream {
            MediaStreamDescriptor::Video(video) => Some(video.as_ref()),
            _ => None,
        })
    }

    pub fn audio_streams(&self) -> impl Iterator<Item = &AudioStreamDescriptor> {
        self.streams.iter().filter_map(|stream| match stream {
            MediaStreamDescriptor::Audio(audio) => Some(audio),
            _ => None,
        })
    }

    pub fn subtitle_streams(&self) -> impl Iterator<Item = &SubtitleStreamDescriptor> {
        self.streams.iter().filter_map(|stream| match stream {
            MediaStreamDescriptor::Subtitle(subtitle) => Some(subtitle),
            _ => None,
        })
    }

    pub fn selected_video(&self) -> Option<&VideoStreamDescriptor> {
        let selected = self.selected_video_stream?;
        self.video_streams().find(|video| video.index == selected)
    }

    pub fn selected_audio(&self) -> Option<&AudioStreamDescriptor> {
        let selected = self.selected_audio_stream?;
        self.audio_streams().find(|audio| audio.index == selected)
    }

    pub fn media_signature(&self) -> String {
        let selected_video = self.selected_video().map(TypedVideoSignature::from);
        let signature = TypedMediaSignature {
            container: self.container,
            selected_video,
        };
        let bytes = serde_json::to_vec(&signature)
            .expect("typed media signature serialization is infallible");
        hex::encode(Sha256::digest(bytes))
    }

    pub(crate) fn estimated_weight(&self) -> usize {
        serde_json::to_vec(self).map_or(MAX_PROBE_STDOUT_BYTES, |bytes| bytes.len())
    }
}

#[derive(Serialize)]
struct TypedMediaSignature<'a> {
    container: ContainerKind,
    selected_video: Option<TypedVideoSignature<'a>>,
}

#[derive(Serialize)]
struct TypedVideoSignature<'a> {
    index: u32,
    codec: InputVideoCodec,
    sample_entry: SampleEntry,
    profile: VideoProfile,
    level: Option<u32>,
    width: Option<u32>,
    height: Option<u32>,
    sample_aspect_ratio: Option<ProbeRational>,
    display_aspect_ratio: Option<ProbeRational>,
    pixel_format: PixelFormat,
    bit_depth: Option<u8>,
    chroma: ChromaSubsampling,
    nominal_frame_rate: Option<RationalRate>,
    average_frame_rate: Option<RationalRate>,
    frame_rate_class: FrameRateClass,
    stream_time_base: Option<ProbeRational>,
    codec_time_base: Option<ProbeRational>,
    field_order: FieldOrder,
    rotation_degrees: Option<i16>,
    color: ColorDescriptor,
    hdr: &'a HdrMetadata,
}

impl<'a> From<&'a VideoStreamDescriptor> for TypedVideoSignature<'a> {
    fn from(video: &'a VideoStreamDescriptor) -> Self {
        Self {
            index: video.index,
            codec: video.codec,
            sample_entry: video.sample_entry,
            profile: video.profile,
            level: video.level,
            width: video.width,
            height: video.height,
            sample_aspect_ratio: video.sample_aspect_ratio,
            display_aspect_ratio: video.display_aspect_ratio,
            pixel_format: video.pixel_format,
            bit_depth: video.bit_depth,
            chroma: video.chroma,
            nominal_frame_rate: video.nominal_frame_rate,
            average_frame_rate: video.average_frame_rate,
            frame_rate_class: video.frame_rate_class,
            stream_time_base: video.stream_time_base,
            codec_time_base: video.codec_time_base,
            field_order: video.field_order,
            rotation_degrees: video.rotation_degrees,
            color: video.color,
            hdr: &video.hdr,
        }
    }
}

#[derive(Deserialize)]
struct RawProbe {
    #[serde(default)]
    format: RawFormat,
    #[serde(default)]
    streams: Vec<RawStream>,
    #[serde(default)]
    chapters: Vec<RawChapter>,
}

#[derive(Default, Deserialize)]
struct RawFormat {
    format_name: Option<String>,
    start_time: Option<String>,
    duration: Option<String>,
    bit_rate: Option<String>,
}

#[derive(Deserialize)]
struct RawStream {
    index: u32,
    codec_type: Option<String>,
    codec_name: Option<String>,
    codec_tag_string: Option<String>,
    profile: Option<String>,
    level: Option<u32>,
    start_time: Option<String>,
    duration: Option<String>,
    width: Option<u32>,
    height: Option<u32>,
    sample_aspect_ratio: Option<String>,
    display_aspect_ratio: Option<String>,
    pix_fmt: Option<String>,
    bits_per_raw_sample: Option<String>,
    bits_per_sample: Option<u8>,
    r_frame_rate: Option<String>,
    avg_frame_rate: Option<String>,
    time_base: Option<String>,
    codec_time_base: Option<String>,
    field_order: Option<String>,
    color_range: Option<String>,
    color_space: Option<String>,
    color_transfer: Option<String>,
    color_primaries: Option<String>,
    bit_rate: Option<String>,
    sample_rate: Option<String>,
    channels: Option<u16>,
    channel_layout: Option<String>,
    #[serde(default)]
    tags: HashMap<String, String>,
    #[serde(default)]
    disposition: HashMap<String, i64>,
    #[serde(default, alias = "side_data")]
    side_data_list: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct RawChapter {
    id: i64,
    start_time: Option<String>,
    end_time: Option<String>,
    #[serde(default)]
    tags: HashMap<String, String>,
}

pub fn parse_probe_document(bytes: &[u8]) -> Result<ProbeDocument, ProbeError> {
    if bytes.len() > MAX_PROBE_STDOUT_BYTES {
        return Err(ProbeError::new(ProbeErrorCode::OutputTooLarge));
    }
    validate_json_shape(bytes)?;
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| ProbeError::new(ProbeErrorCode::MalformedOutput))?;
    validate_json_value(&value, 0, &mut 0)?;
    let raw: RawProbe = serde_json::from_value(value)
        .map_err(|_| ProbeError::new(ProbeErrorCode::MalformedOutput))?;
    if raw.streams.len() > MAX_STREAMS || raw.chapters.len() > MAX_CHAPTERS {
        return Err(ProbeError::new(ProbeErrorCode::LimitExceeded));
    }

    let mut streams = Vec::with_capacity(raw.streams.len());
    let mut stream_indices = HashSet::with_capacity(raw.streams.len());
    for raw_stream in raw.streams {
        if !stream_indices.insert(raw_stream.index) {
            return Err(ProbeError::new(ProbeErrorCode::MalformedOutput));
        }
        if raw_stream.tags.len() > 64 || raw_stream.side_data_list.len() > MAX_SIDE_DATA_PER_STREAM
        {
            return Err(ProbeError::new(ProbeErrorCode::LimitExceeded));
        }
        streams.push(parse_stream(raw_stream)?);
    }
    streams.sort_by_key(stream_index);
    let chapters = raw
        .chapters
        .into_iter()
        .map(parse_chapter)
        .collect::<Result<Vec<_>, _>>()?;
    let selected_video_stream = select_stream(&streams, true);
    let selected_audio_stream = select_stream(&streams, false);

    Ok(ProbeDocument {
        container: ContainerKind::from_probe(raw.format.format_name.as_deref()),
        container_display: SafeProbeText::parse(raw.format.format_name.as_deref(), "unknown")?,
        start_micros: parse_signed_micros(raw.format.start_time.as_deref()),
        duration_micros: parse_unsigned_micros(raw.format.duration.as_deref()),
        bitrate: parse_u64_text(raw.format.bit_rate.as_deref()),
        streams,
        chapters,
        selected_video_stream,
        selected_audio_stream,
    })
}

fn validate_json_shape(bytes: &[u8]) -> Result<(), ProbeError> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut string_len = 0usize;
    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
                string_len = 0;
            } else {
                string_len = string_len.saturating_add(1);
                if string_len > MAX_JSON_STRING_BYTES {
                    return Err(ProbeError::new(ProbeErrorCode::LimitExceeded));
                }
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                if depth > MAX_JSON_DEPTH {
                    return Err(ProbeError::new(ProbeErrorCode::LimitExceeded));
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    if in_string || depth != 0 {
        return Err(ProbeError::new(ProbeErrorCode::MalformedOutput));
    }
    Ok(())
}

fn validate_json_value(
    value: &serde_json::Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), ProbeError> {
    if depth > MAX_JSON_DEPTH {
        return Err(ProbeError::new(ProbeErrorCode::LimitExceeded));
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_JSON_NODES {
        return Err(ProbeError::new(ProbeErrorCode::LimitExceeded));
    }
    match value {
        serde_json::Value::String(value) if value.len() > MAX_JSON_STRING_BYTES => {
            Err(ProbeError::new(ProbeErrorCode::LimitExceeded))
        }
        serde_json::Value::Array(values) => values
            .iter()
            .try_for_each(|value| validate_json_value(value, depth + 1, nodes)),
        serde_json::Value::Object(values) => values
            .values()
            .try_for_each(|value| validate_json_value(value, depth + 1, nodes)),
        _ => Ok(()),
    }
}

fn parse_stream(raw: RawStream) -> Result<MediaStreamDescriptor, ProbeError> {
    let disposition = parse_disposition(&raw.disposition);
    let language = optional_safe_text(raw.tags.get("language"))?;
    match raw.codec_type.as_deref() {
        Some("video") => {
            let codec = InputVideoCodec::from_probe(raw.codec_name.as_deref());
            let pixel_format = PixelFormat::from_probe(raw.pix_fmt.as_deref());
            let nominal_frame_rate = parse_rate(raw.r_frame_rate.as_deref());
            let average_frame_rate = parse_rate(raw.avg_frame_rate.as_deref());
            let frame_rate_class = match (nominal_frame_rate, average_frame_rate) {
                (Some(nominal), Some(average)) if nominal == average => FrameRateClass::Constant,
                (Some(_), Some(_)) => FrameRateClass::Variable,
                _ => FrameRateClass::Unknown,
            };
            let (side_data_rotation, hdr) = parse_side_data(&raw.side_data_list)?;
            let rotation_degrees = side_data_rotation.or_else(|| {
                raw.tags
                    .get("rotate")
                    .and_then(|value| value.parse::<i16>().ok())
                    .filter(|value| (-360..=360).contains(value))
            });
            let bit_depth = parse_u8_text(raw.bits_per_raw_sample.as_deref())
                .or(raw.bits_per_sample)
                .filter(|depth| (1..=16).contains(depth))
                .or_else(|| pixel_format.inferred_bit_depth());
            Ok(MediaStreamDescriptor::Video(Box::new(
                VideoStreamDescriptor {
                    index: raw.index,
                    codec,
                    codec_display: SafeProbeText::parse(raw.codec_name.as_deref(), "unknown")?,
                    sample_entry: SampleEntry::from_probe(raw.codec_tag_string.as_deref()),
                    codec_tag: optional_safe_text(raw.codec_tag_string.as_ref())?,
                    profile: VideoProfile::from_probe(codec, raw.profile.as_deref()),
                    profile_display: optional_safe_text(raw.profile.as_ref())?,
                    level: raw.level,
                    start_micros: parse_signed_micros(raw.start_time.as_deref()),
                    duration_micros: parse_unsigned_micros(raw.duration.as_deref()),
                    width: raw.width.filter(|value| *value > 0),
                    height: raw.height.filter(|value| *value > 0),
                    sample_aspect_ratio: parse_ratio(raw.sample_aspect_ratio.as_deref()),
                    display_aspect_ratio: parse_ratio(raw.display_aspect_ratio.as_deref()),
                    pixel_format,
                    pixel_format_display: optional_safe_text(raw.pix_fmt.as_ref())?,
                    bit_depth,
                    chroma: pixel_format.chroma(),
                    nominal_frame_rate,
                    average_frame_rate,
                    frame_rate_class,
                    stream_time_base: parse_ratio(raw.time_base.as_deref()),
                    codec_time_base: parse_ratio(raw.codec_time_base.as_deref()),
                    field_order: FieldOrder::from_probe(raw.field_order.as_deref()),
                    rotation_degrees,
                    color: ColorDescriptor {
                        primaries: ColorPrimaries::from_probe(raw.color_primaries.as_deref()),
                        transfer: ColorTransfer::from_probe(raw.color_transfer.as_deref()),
                        matrix: ColorMatrix::from_probe(raw.color_space.as_deref()),
                        range: ColorRange::from_probe(raw.color_range.as_deref()),
                    },
                    hdr,
                    bitrate: parse_u64_text(raw.bit_rate.as_deref()),
                    language,
                    disposition,
                },
            )))
        }
        Some("audio") => Ok(MediaStreamDescriptor::Audio(AudioStreamDescriptor {
            index: raw.index,
            codec_display: SafeProbeText::parse(raw.codec_name.as_deref(), "unknown")?,
            codec_tag: optional_safe_text(raw.codec_tag_string.as_ref())?,
            profile_display: optional_safe_text(raw.profile.as_ref())?,
            start_micros: parse_signed_micros(raw.start_time.as_deref()),
            duration_micros: parse_unsigned_micros(raw.duration.as_deref()),
            stream_time_base: parse_ratio(raw.time_base.as_deref()),
            sample_rate: parse_u32_text(raw.sample_rate.as_deref()),
            channels: raw.channels,
            channel_layout: optional_safe_text(raw.channel_layout.as_ref())?,
            bitrate: parse_u64_text(raw.bit_rate.as_deref()),
            language,
            disposition,
        })),
        Some("subtitle") => Ok(MediaStreamDescriptor::Subtitle(SubtitleStreamDescriptor {
            index: raw.index,
            codec_display: SafeProbeText::parse(raw.codec_name.as_deref(), "unknown")?,
            codec_tag: optional_safe_text(raw.codec_tag_string.as_ref())?,
            start_micros: parse_signed_micros(raw.start_time.as_deref()),
            duration_micros: parse_unsigned_micros(raw.duration.as_deref()),
            stream_time_base: parse_ratio(raw.time_base.as_deref()),
            language,
            disposition,
        })),
        _ => Ok(MediaStreamDescriptor::Other {
            index: raw.index,
            track_display: SafeProbeText::parse(raw.codec_type.as_deref(), "other")?,
            codec_display: SafeProbeText::parse(raw.codec_name.as_deref(), "unknown")?,
            codec_tag: optional_safe_text(raw.codec_tag_string.as_ref())?,
            start_micros: parse_signed_micros(raw.start_time.as_deref()),
            duration_micros: parse_unsigned_micros(raw.duration.as_deref()),
            stream_time_base: parse_ratio(raw.time_base.as_deref()),
        }),
    }
}

fn parse_chapter(raw: RawChapter) -> Result<ChapterDescriptor, ProbeError> {
    if raw.tags.len() > 64 {
        return Err(ProbeError::new(ProbeErrorCode::LimitExceeded));
    }
    Ok(ChapterDescriptor {
        id: raw.id,
        start_micros: parse_signed_micros(raw.start_time.as_deref()),
        end_micros: parse_signed_micros(raw.end_time.as_deref()),
        title: optional_safe_text(raw.tags.get("title"))?,
    })
}

fn select_stream(streams: &[MediaStreamDescriptor], video: bool) -> Option<u32> {
    let matching = |stream: &MediaStreamDescriptor| match (video, stream) {
        (true, MediaStreamDescriptor::Video(stream)) if !stream.disposition.attached_picture => {
            Some((stream.index, stream.disposition.default))
        }
        (false, MediaStreamDescriptor::Audio(stream)) => {
            Some((stream.index, stream.disposition.default))
        }
        _ => None,
    };
    streams
        .iter()
        .filter_map(matching)
        .find(|(_, is_default)| *is_default)
        .or_else(|| streams.iter().filter_map(matching).next())
        .map(|(index, _)| index)
}

fn stream_index(stream: &MediaStreamDescriptor) -> u32 {
    match stream {
        MediaStreamDescriptor::Video(stream) => stream.index,
        MediaStreamDescriptor::Audio(stream) => stream.index,
        MediaStreamDescriptor::Subtitle(stream) => stream.index,
        MediaStreamDescriptor::Other { index, .. } => *index,
    }
}

fn parse_disposition(raw: &HashMap<String, i64>) -> StreamDisposition {
    let enabled = |name: &str| raw.get(name).copied().unwrap_or_default() == 1;
    StreamDisposition {
        default: enabled("default"),
        forced: enabled("forced"),
        hearing_impaired: enabled("hearing_impaired"),
        visual_impaired: enabled("visual_impaired"),
        attached_picture: enabled("attached_pic"),
    }
}

fn parse_side_data(values: &[serde_json::Value]) -> Result<(Option<i16>, HdrMetadata), ProbeError> {
    let mut rotation = None;
    let mut hdr = HdrMetadata::default();
    for value in values {
        let Some(object) = value.as_object() else {
            continue;
        };
        let kind = object
            .get("side_data_type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if let Some(raw_rotation) = object.get("rotation").and_then(serde_json::Value::as_i64) {
            let parsed = i16::try_from(raw_rotation)
                .ok()
                .filter(|value| (-360..=360).contains(value));
            if rotation.is_some() && parsed != rotation {
                return Err(ProbeError::new(ProbeErrorCode::MalformedOutput));
            }
            rotation = parsed.or(rotation);
        }
        match kind {
            "Mastering display metadata" => {
                if hdr.mastering_display.is_some() {
                    return Err(ProbeError::new(ProbeErrorCode::MalformedOutput));
                }
                let rational = |name: &str| {
                    object
                        .get(name)
                        .and_then(serde_json::Value::as_str)
                        .and_then(|value| parse_ratio(Some(value)))
                };
                hdr.mastering_display = Some(MasteringDisplayMetadata {
                    red_x: rational("red_x"),
                    red_y: rational("red_y"),
                    green_x: rational("green_x"),
                    green_y: rational("green_y"),
                    blue_x: rational("blue_x"),
                    blue_y: rational("blue_y"),
                    white_point_x: rational("white_point_x"),
                    white_point_y: rational("white_point_y"),
                    min_luminance: rational("min_luminance"),
                    max_luminance: rational("max_luminance"),
                });
            }
            "Content light level metadata" => {
                if hdr.content_light.is_some() {
                    return Err(ProbeError::new(ProbeErrorCode::MalformedOutput));
                }
                hdr.content_light = Some(ContentLightMetadata {
                    max_content: json_u32(object.get("max_content")),
                    max_average: json_u32(object.get("max_average")),
                });
            }
            "DOVI configuration record" | "Dolby Vision configuration record" => {
                if hdr.dolby_vision.is_some() {
                    return Err(ProbeError::new(ProbeErrorCode::MalformedOutput));
                }
                hdr.dolby_vision = Some(DolbyVisionMetadata {
                    profile: json_u8(object.get("dv_profile")),
                    level: json_u8(object.get("dv_level")),
                    rpu_present: json_bool_flag(object.get("rpu_present_flag")),
                    enhancement_layer_present: json_bool_flag(object.get("el_present_flag")),
                    base_layer_present: json_bool_flag(object.get("bl_present_flag")),
                });
            }
            _ => {}
        }
    }
    Ok((rotation, hdr))
}

fn json_u32(value: Option<&serde_json::Value>) -> Option<u32> {
    value
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
}
fn json_u8(value: Option<&serde_json::Value>) -> Option<u8> {
    value
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u8::try_from(value).ok())
}
fn json_bool_flag(value: Option<&serde_json::Value>) -> Option<bool> {
    value
        .and_then(serde_json::Value::as_i64)
        .and_then(|value| match value {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        })
}
fn optional_safe_text(value: Option<&String>) -> Result<Option<SafeProbeText>, ProbeError> {
    value
        .filter(|value| !value.is_empty())
        .map(|value| SafeProbeText::parse(Some(value), "unknown"))
        .transpose()
}
fn parse_u64_text(value: Option<&str>) -> Option<u64> {
    value?.parse().ok()
}
fn parse_u32_text(value: Option<&str>) -> Option<u32> {
    value?.parse().ok()
}
fn parse_u8_text(value: Option<&str>) -> Option<u8> {
    value?.parse().ok()
}
fn parse_signed_micros(value: Option<&str>) -> Option<i64> {
    let seconds = value?.parse::<f64>().ok()?;
    if !seconds.is_finite() {
        return None;
    }
    let micros = seconds * 1_000_000.0;
    (micros >= i64::MIN as f64 && micros <= i64::MAX as f64).then(|| micros.round() as i64)
}
fn parse_unsigned_micros(value: Option<&str>) -> Option<u64> {
    let seconds = value?.parse::<f64>().ok()?;
    if !seconds.is_finite() || seconds < 0.0 {
        return None;
    }
    let micros = seconds * 1_000_000.0;
    (micros <= u64::MAX as f64).then(|| micros.round() as u64)
}
fn parse_rate(value: Option<&str>) -> Option<RationalRate> {
    let ratio = parse_ratio(value)?;
    let numerator = u32::try_from(ratio.numerator).ok()?;
    let denominator = u32::try_from(ratio.denominator)
        .ok()
        .and_then(NonZeroU32::new)?;
    RationalRate::new(numerator, denominator).ok()
}
fn parse_ratio(value: Option<&str>) -> Option<ProbeRational> {
    let value = value?;
    let (numerator, denominator) = value.split_once('/').or_else(|| value.split_once(':'))?;
    let mut numerator = numerator.parse::<i64>().ok()?;
    let mut denominator = denominator.parse::<i64>().ok()?;
    if denominator == 0 || numerator == 0 {
        return None;
    }
    if denominator < 0 {
        numerator = numerator.checked_neg()?;
        denominator = denominator.checked_neg()?;
    }
    let denominator = u64::try_from(denominator).ok()?;
    let divisor = gcd_u64(numerator.unsigned_abs(), denominator);
    Some(ProbeRational {
        numerator: numerator / i64::try_from(divisor).ok()?,
        denominator: denominator / divisor,
    })
}
fn gcd_u64(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left.max(1)
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct ProbeCacheKey {
    source_policy: super::source::SourceProtocolPolicy,
    source_version: String,
}

struct CacheEntry {
    value: Arc<ProbeDocument>,
    expires_at: Instant,
    weight: usize,
}

struct ProbeFlight {
    notify: Notify,
    result: Mutex<Option<Result<Arc<ProbeDocument>, ProbeError>>>,
}

#[derive(Default)]
struct ProbeCacheState {
    entries: HashMap<ProbeCacheKey, CacheEntry>,
    lru: VecDeque<ProbeCacheKey>,
    in_flight: HashMap<ProbeCacheKey, Arc<ProbeFlight>>,
    weight: usize,
}

pub(crate) struct ProbeCache {
    state: Mutex<ProbeCacheState>,
    ttl: Duration,
    max_entries: usize,
    max_weight: usize,
    max_in_flight: usize,
}

struct FlightLeaderGuard<'a> {
    cache: &'a ProbeCache,
    key: ProbeCacheKey,
    flight: Arc<ProbeFlight>,
    completed: bool,
}

impl Drop for FlightLeaderGuard<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let cancelled = Err(ProbeError::new(ProbeErrorCode::Cancelled));
        let mut result = self
            .flight
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if result.is_none() {
            *result = Some(cancelled);
        }
        drop(result);
        let mut state = self
            .cache
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state
            .in_flight
            .get(&self.key)
            .is_some_and(|current| Arc::ptr_eq(current, &self.flight))
        {
            state.in_flight.remove(&self.key);
        }
        drop(state);
        self.flight.notify.notify_waiters();
    }
}

impl Default for ProbeCache {
    fn default() -> Self {
        Self {
            state: Mutex::new(ProbeCacheState::default()),
            ttl: CACHE_TTL,
            max_entries: CACHE_MAX_ENTRIES,
            max_weight: CACHE_MAX_WEIGHT,
            max_in_flight: CACHE_MAX_IN_FLIGHT,
        }
    }
}

impl ProbeCache {
    #[cfg(test)]
    fn with_limits(
        ttl: Duration,
        max_entries: usize,
        max_weight: usize,
        max_in_flight: usize,
    ) -> Self {
        Self {
            state: Mutex::new(ProbeCacheState::default()),
            ttl,
            max_entries,
            max_weight,
            max_in_flight,
        }
    }

    async fn get_or_probe<F, Fut>(
        &self,
        key: ProbeCacheKey,
        probe: F,
    ) -> Result<Arc<ProbeDocument>, ProbeError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Arc<ProbeDocument>, ProbeError>>,
    {
        let (flight, leader) = {
            let now = Instant::now();
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(value) = state
                .entries
                .get(&key)
                .filter(|entry| entry.expires_at > now)
                .map(|entry| entry.value.clone())
            {
                state.lru.retain(|candidate| candidate != &key);
                state.lru.push_back(key.clone());
                return Ok(value);
            }
            remove_cache_entry(&mut state, &key);
            if let Some(flight) = state.in_flight.get(&key) {
                (flight.clone(), false)
            } else {
                if state.in_flight.len() >= self.max_in_flight {
                    return Err(ProbeError::new(ProbeErrorCode::CapacityExceeded));
                }
                let flight = Arc::new(ProbeFlight {
                    notify: Notify::new(),
                    result: Mutex::new(None),
                });
                state.in_flight.insert(key.clone(), flight.clone());
                (flight, true)
            }
        };
        if !leader {
            loop {
                let notified = flight.notify.notified();
                if let Some(result) = flight
                    .result
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
                {
                    return result;
                }
                notified.await;
            }
        }

        let mut leader_guard = FlightLeaderGuard {
            cache: self,
            key: key.clone(),
            flight: flight.clone(),
            completed: false,
        };
        let result = probe().await;
        {
            let mut slot = flight
                .result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *slot = Some(result.clone());
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.in_flight.remove(&key);
        if let Ok(value) = &result {
            let weight = value.estimated_weight().min(self.max_weight);
            state.weight = state.weight.saturating_add(weight);
            state.lru.push_back(key.clone());
            state.entries.insert(
                key,
                CacheEntry {
                    value: value.clone(),
                    expires_at: Instant::now() + self.ttl,
                    weight,
                },
            );
            while state.entries.len() > self.max_entries || state.weight > self.max_weight {
                let Some(oldest) = state.lru.pop_front() else {
                    break;
                };
                remove_cache_entry(&mut state, &oldest);
            }
        }
        drop(state);
        flight.notify.notify_waiters();
        leader_guard.completed = true;
        result
    }
}

fn remove_cache_entry(state: &mut ProbeCacheState, key: &ProbeCacheKey) {
    if let Some(entry) = state.entries.remove(key) {
        state.weight = state.weight.saturating_sub(entry.weight);
    }
    state.lru.retain(|candidate| candidate != key);
}

pub async fn probe_media(
    service: &TranscodingService,
    source: &ValidatedMediaSource,
) -> Result<Arc<MediaDescriptor>, ProbeError> {
    let key = ProbeCacheKey {
        source_policy: source.protocol_policy(),
        source_version: source.version().to_owned(),
    };
    let document = service
        .probe_cache()
        .get_or_probe(key, || async {
            run_probe(service, source).await.map(Arc::new)
        })
        .await?;
    Ok(Arc::new(MediaDescriptor::from_probe(
        source.clone(),
        document.as_ref().clone(),
    )))
}

async fn run_probe(
    service: &TranscodingService,
    source: &ValidatedMediaSource,
) -> Result<ProbeDocument, ProbeError> {
    let session = service
        .runtime_for_session()
        .await
        .map_err(|_| ProbeError::new(ProbeErrorCode::RuntimeUnavailable))?;
    let input = source.input_argument().map_err(map_source_error)?;
    let command = probe_command(source, input);
    let cancellation = CancellationToken::new();
    let process =
        session.run_bounded_with_cancellation(RuntimeExecutable::Ffprobe, command, &cancellation);
    tokio::pin!(process);
    let watchdog = watch_probe_activity(source.subscribe_activity());
    tokio::pin!(watchdog);
    let output = tokio::select! {
        output = &mut process => output.map_err(map_runtime_error)?,
        reason = &mut watchdog => {
            cancellation.cancel();
            let _ = process.await;
            return Err(reason);
        }
    };
    if !output.status.success() {
        return Err(ProbeError::new(ProbeErrorCode::NonZeroExit));
    }
    parse_probe_document(&output.stdout)
}

fn probe_command(source: &ValidatedMediaSource, input: OsString) -> RuntimeCommand {
    const ENTRIES: &str = "format=format_name,duration,start_time,bit_rate:stream=index,codec_type,codec_name,codec_tag_string,profile,level,start_time,duration,width,height,sample_aspect_ratio,display_aspect_ratio,pix_fmt,bits_per_raw_sample,bits_per_sample,r_frame_rate,avg_frame_rate,time_base,codec_time_base,field_order,color_range,color_space,color_transfer,color_primaries,bit_rate,sample_rate,channels,channel_layout:stream_tags=language,rotate:stream_disposition=default,forced,hearing_impaired,visual_impaired,attached_pic:side_data=side_data_type,rotation,red_x,red_y,green_x,green_y,blue_x,blue_y,white_point_x,white_point_y,min_luminance,max_luminance,max_content,max_average,dv_profile,dv_level,rpu_present_flag,el_present_flag,bl_present_flag:chapter=id,start_time,end_time:chapter_tags=title";
    RuntimeCommand::new(
        vec![
            "-v".into(),
            "error".into(),
            "-protocol_whitelist".into(),
            source.ffmpeg_protocol_allowlist().into(),
            "-of".into(),
            "json".into(),
            "-show_format".into(),
            "-show_streams".into(),
            "-show_chapters".into(),
            "-show_entries".into(),
            ENTRIES.into(),
            input,
        ],
        StdoutPolicy::Capture {
            byte_limit: MAX_PROBE_STDOUT_BYTES,
        },
        MAX_PROBE_STDERR_BYTES,
        PROBE_HARD_DEADLINE,
    )
}

async fn watch_probe_activity(
    mut activity: tokio::sync::watch::Receiver<SourceActivitySnapshot>,
) -> ProbeError {
    let started = Instant::now();
    let hard_deadline = started + PROBE_HARD_DEADLINE;
    let mut last = activity.borrow_and_update().clone();
    let mut starved = is_confirmed_starvation(&last);
    let mut inactivity_remaining = PROBE_INACTIVITY;
    let mut inactivity_started = started;
    let mut starvation_remaining = PROBE_STARVATION_DEFAULT;
    let mut starvation_started = started;
    loop {
        let now = Instant::now();
        if now >= hard_deadline {
            return ProbeError::new(ProbeErrorCode::OverallDeadline);
        }
        let deadline = if starved {
            (starvation_started + starvation_remaining).min(hard_deadline)
        } else {
            (inactivity_started + inactivity_remaining).min(hard_deadline)
        };
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                return ProbeError::new(if deadline == hard_deadline { ProbeErrorCode::OverallDeadline } else if starved { ProbeErrorCode::SourceStarvation } else { ProbeErrorCode::Inactivity });
            }
            changed = activity.changed() => {
                if changed.is_err() {
                    tokio::time::sleep_until(deadline).await;
                    return ProbeError::new(if deadline == hard_deadline {
                        ProbeErrorCode::OverallDeadline
                    } else if starved {
                        ProbeErrorCode::SourceStarvation
                    } else {
                        ProbeErrorCode::Inactivity
                    });
                }
                let now = Instant::now();
                let next = activity.borrow_and_update().clone();
                let next_starved = is_confirmed_starvation(&next);
                if starved {
                    starvation_remaining = starvation_remaining.saturating_sub(now.saturating_duration_since(starvation_started));
                } else {
                    inactivity_remaining = inactivity_remaining.saturating_sub(now.saturating_duration_since(inactivity_started));
                }
                if next.delivered_bytes_total > last.delivered_bytes_total {
                    inactivity_remaining = PROBE_INACTIVITY;
                }
                starved = next_starved;
                if starved { starvation_started = now; } else { inactivity_started = now; }
                last = next;
            }
        }
    }
}

fn is_confirmed_starvation(snapshot: &SourceActivitySnapshot) -> bool {
    snapshot.active_requests > 0 && snapshot.all_active_requests_piece_blocked
}

fn map_source_error(_: SourceError) -> ProbeError {
    ProbeError::new(ProbeErrorCode::SourceInvalid)
}
fn map_runtime_error(error: RuntimeCommandError) -> ProbeError {
    match error {
        RuntimeCommandError::Runtime(_) => ProbeError::new(ProbeErrorCode::RuntimeUnavailable),
        RuntimeCommandError::Process(error) => {
            ProbeError::new(map_process_error_code(error.code()))
        }
    }
}

fn map_process_error_code(code: ProcessErrorCode) -> ProbeErrorCode {
    match code {
        ProcessErrorCode::Cancelled => ProbeErrorCode::Cancelled,
        ProcessErrorCode::DeadlineExceeded => ProbeErrorCode::OverallDeadline,
        ProcessErrorCode::StdoutLimitExceeded => ProbeErrorCode::OutputTooLarge,
        _ => ProbeErrorCode::ProcessFailure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn supervisor_deadline_is_the_probe_hard_overall_deadline() {
        assert_eq!(
            map_process_error_code(ProcessErrorCode::DeadlineExceeded),
            ProbeErrorCode::OverallDeadline
        );
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_ignores_non_source_output_and_pauses_only_for_all_blocked_source_requests() {
        let (sender, receiver) = tokio::sync::watch::channel(SourceActivitySnapshot::default());
        let watchdog = tokio::spawn(watch_probe_activity(receiver));
        tokio::time::advance(Duration::from_secs(29)).await;
        assert!(!watchdog.is_finished());
        sender.send_modify(|snapshot| {
            snapshot.sequence += 1;
            snapshot.active_requests = 1;
            snapshot.all_active_requests_piece_blocked = true;
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(9 * 60)).await;
        assert!(!watchdog.is_finished());
        sender.send_modify(|snapshot| {
            snapshot.sequence += 1;
            snapshot.delivered_bytes_total += 1;
            snapshot.all_active_requests_piece_blocked = false;
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(29)).await;
        assert!(!watchdog.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(watchdog.await.unwrap().code(), ProbeErrorCode::Inactivity);
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_enforces_default_starvation_and_hard_overall_deadlines() {
        let (sender, receiver) = tokio::sync::watch::channel(SourceActivitySnapshot::default());
        sender.send_modify(|snapshot| {
            snapshot.active_requests = 1;
            snapshot.all_active_requests_piece_blocked = true;
        });
        let watchdog = tokio::spawn(watch_probe_activity(receiver));
        tokio::time::advance(PROBE_STARVATION_DEFAULT).await;
        assert_eq!(
            watchdog.await.unwrap().code(),
            ProbeErrorCode::SourceStarvation
        );

        let (sender, receiver) = tokio::sync::watch::channel(SourceActivitySnapshot::default());
        let hard_watchdog = tokio::spawn(watch_probe_activity(receiver));
        tokio::task::yield_now().await;
        for delivered in 1..=62 {
            tokio::time::advance(Duration::from_secs(29)).await;
            sender.send_modify(|snapshot| {
                snapshot.sequence += 1;
                snapshot.active_requests = 1;
                snapshot.delivered_bytes_total = delivered;
                snapshot.all_active_requests_piece_blocked = false;
            });
            tokio::task::yield_now().await;
            assert!(!hard_watchdog.is_finished());
        }
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(
            hard_watchdog.await.unwrap().code(),
            ProbeErrorCode::OverallDeadline
        );
    }

    #[tokio::test]
    async fn cache_single_flights_and_versions_invalidate() {
        let cache = Arc::new(ProbeCache::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let document = parse_probe_document(br#"{"format":{},"streams":[]}"#).unwrap();
        let value = Arc::new(document);
        let key = ProbeCacheKey {
            source_policy: super::super::source::SourceProtocolPolicy::CompletedFile,
            source_version: "v1".into(),
        };
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let cache = cache.clone();
            let calls = calls.clone();
            let value = value.clone();
            let key = key.clone();
            tasks.push(tokio::spawn(async move {
                cache
                    .get_or_probe(key, || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                        Ok(value)
                    })
                    .await
                    .unwrap()
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let version_two = ProbeCacheKey {
            source_version: "v2".into(),
            ..key
        };
        cache
            .get_or_probe(version_two, || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(value)
            })
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cancelled_cache_leader_does_not_strand_followers() {
        let cache = Arc::new(ProbeCache::default());
        let key = ProbeCacheKey {
            source_policy: super::super::source::SourceProtocolPolicy::CompletedFile,
            source_version: "v1".into(),
        };
        let started = Arc::new(Notify::new());
        let leader = {
            let cache = cache.clone();
            let key = key.clone();
            let started = started.clone();
            tokio::spawn(async move {
                cache
                    .get_or_probe(key, || async move {
                        started.notify_one();
                        std::future::pending().await
                    })
                    .await
            })
        };
        started.notified().await;
        leader.abort();
        let _ = leader.await;

        let follower = cache.get_or_probe(key, || async {
            Err(ProbeError::new(ProbeErrorCode::ProcessFailure))
        });
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), follower)
                .await
                .expect("follower must not wait on an abandoned flight")
                .unwrap_err()
                .code(),
            ProbeErrorCode::ProcessFailure
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cache_ttl_expiry_reprobes() {
        let cache = ProbeCache::default();
        let calls = AtomicUsize::new(0);
        let document = parse_probe_document(br#"{"format":{},"streams":[]}"#).unwrap();
        let value = Arc::new(document);
        let key = ProbeCacheKey {
            source_policy: super::super::source::SourceProtocolPolicy::CompletedFile,
            source_version: "v1".into(),
        };

        for _ in 0..2 {
            cache
                .get_or_probe(key.clone(), || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(value.clone())
                })
                .await
                .unwrap();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(CACHE_TTL + Duration::from_secs(1)).await;
        cache
            .get_or_probe(key, || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(value)
            })
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cache_lru_enforces_count_and_weight_bounds() {
        let document = Arc::new(
            parse_probe_document(include_bytes!(
                "../../tests/fixtures/ffprobe/compatibility.json"
            ))
            .unwrap(),
        );
        let weight = document.estimated_weight();
        let cache = ProbeCache::with_limits(CACHE_TTL, 2, usize::MAX, CACHE_MAX_IN_FLIGHT);
        let key = |version: &str| ProbeCacheKey {
            source_policy: super::super::source::SourceProtocolPolicy::CompletedFile,
            source_version: version.to_owned(),
        };
        for version in ["a", "b"] {
            cache
                .get_or_probe(key(version), || async { Ok(document.clone()) })
                .await
                .unwrap();
        }
        cache
            .get_or_probe(key("a"), || async { unreachable!("cache hit") })
            .await
            .unwrap();
        cache
            .get_or_probe(key("c"), || async { Ok(document.clone()) })
            .await
            .unwrap();
        {
            let state = cache
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(state.entries.contains_key(&key("a")));
            assert!(!state.entries.contains_key(&key("b")));
            assert!(state.entries.contains_key(&key("c")));
        }

        let weighted = ProbeCache::with_limits(CACHE_TTL, 10, weight * 2 - 1, CACHE_MAX_IN_FLIGHT);
        for version in ["a", "b"] {
            weighted
                .get_or_probe(key(version), || async { Ok(document.clone()) })
                .await
                .unwrap();
        }
        let state = weighted
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(state.entries.len(), 1);
        assert!(state.weight < weight * 2);
    }

    #[test]
    fn ffprobe_recipe_is_closed_and_uses_only_the_source_protocol_policy() {
        let local = ValidatedMediaSource::completed_file("local-source").unwrap();
        let local_command = probe_command(&local, OsString::from(r"C:\media\fixture.mkv"));
        let local_args = local_command
            .args()
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            local_args
                .windows(2)
                .find(|pair| pair[0] == "-protocol_whitelist")
                .map(|pair| pair[1].as_str()),
            Some("file,pipe")
        );
        assert_eq!(local_args.last().unwrap(), r"C:\media\fixture.mkv");
        assert!(
            local_args
                .iter()
                .any(|argument| argument == "-show_entries")
        );
        assert!(!local_args.iter().any(|argument| argument.contains("https")));

        let engine = ValidatedMediaSource::engine_loopback("engine-source").unwrap();
        let engine_command = probe_command(&engine, OsString::from("http://127.0.0.1/source"));
        let engine_args = engine_command
            .args()
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            engine_args
                .windows(2)
                .find(|pair| pair[0] == "-protocol_whitelist")
                .map(|pair| pair[1].as_str()),
            Some("http,tcp")
        );
    }

    #[tokio::test]
    async fn cache_bounds_distinct_in_flight_probes_without_blocking_same_key_followers() {
        let cache = Arc::new(ProbeCache::with_limits(CACHE_TTL, 8, usize::MAX, 1));
        let started = Arc::new(Notify::new());
        let first_key = ProbeCacheKey {
            source_policy: super::super::source::SourceProtocolPolicy::CompletedFile,
            source_version: "first".into(),
        };
        let leader = {
            let cache = cache.clone();
            let started = started.clone();
            tokio::spawn(async move {
                cache
                    .get_or_probe(first_key, || async move {
                        started.notify_one();
                        std::future::pending().await
                    })
                    .await
            })
        };
        started.notified().await;
        let second_key = ProbeCacheKey {
            source_policy: super::super::source::SourceProtocolPolicy::CompletedFile,
            source_version: "second".into(),
        };
        let error = cache
            .get_or_probe(second_key, || async {
                unreachable!("must reject before work")
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), ProbeErrorCode::CapacityExceeded);
        leader.abort();
        let _ = leader.await;
    }
}
