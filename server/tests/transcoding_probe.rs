use stream_server::transcoding::{
    ChromaSubsampling, ColorMatrix, ColorPrimaries, ColorRange, ColorTransfer, FieldOrder,
    FrameRateClass, InputVideoCodec, PixelFormat, VideoProfile, parse_probe_document,
};

#[test]
fn complete_fixture_parses_all_supported_input_families_and_selects_default_stream() {
    let parsed = parse_probe_document(include_bytes!("fixtures/ffprobe/codec_matrix.json"))
        .expect("parse complete ffprobe fixture");
    let videos = parsed.video_streams().collect::<Vec<_>>();

    assert_eq!(parsed.container_display(), "matroska,webm");
    assert_eq!(parsed.duration_micros(), Some(120_500_000));
    assert_eq!(parsed.start_micros(), Some(125_000));
    assert_eq!(parsed.selected_video_stream(), Some(2));
    assert_eq!(parsed.selected_audio_stream(), Some(20));
    assert_eq!(videos.len(), 11);
    assert_eq!(videos[0].codec(), InputVideoCodec::H264);
    assert_eq!(videos[0].profile(), VideoProfile::H264High);
    assert_eq!(videos[0].pixel_format(), PixelFormat::Yuv420p);
    assert_eq!(videos[0].bit_depth(), Some(8));
    assert_eq!(videos[0].chroma(), ChromaSubsampling::Cs420);
    assert_eq!(videos[0].frame_rate_class(), FrameRateClass::Constant);
    assert_eq!(videos[1].profile(), VideoProfile::H264High10);
    assert_eq!(videos[1].frame_rate_class(), FrameRateClass::Variable);
    assert_eq!(videos[2].codec(), InputVideoCodec::Hevc);
    assert_eq!(videos[3].profile(), VideoProfile::HevcMain10);
    assert_eq!(videos[4].codec(), InputVideoCodec::Av1);
    assert_eq!(videos[5].bit_depth(), Some(10));
    assert_eq!(videos[6].codec(), InputVideoCodec::Vp9);
    assert_eq!(videos[7].profile(), VideoProfile::Vp9Profile2);
    assert_eq!(videos[8].codec(), InputVideoCodec::Mpeg2);
    assert_eq!(videos[9].codec(), InputVideoCodec::Vc1);
    assert_eq!(videos[10].codec(), InputVideoCodec::OtherProbed);
    assert_eq!(videos[10].codec_display(), "future_codec");
    assert_eq!(videos[10].pixel_format(), PixelFormat::OtherProbed);

    let selected = parsed.selected_video().expect("selected video");
    assert_eq!(selected.codec_tag(), Some("avc1"));
    assert_eq!(selected.level(), Some(41));
    assert_eq!(selected.sample_aspect_ratio().unwrap().numerator(), 1);
    assert_eq!(selected.display_aspect_ratio().unwrap().numerator(), 16);
    assert_eq!(selected.stream_time_base().unwrap().denominator(), 1000);
    assert_eq!(selected.codec_time_base().unwrap().numerator(), 1001);
    assert_eq!(selected.field_order(), FieldOrder::Progressive);
    assert_eq!(selected.color().primaries, ColorPrimaries::Bt709);
    assert_eq!(selected.color().transfer, ColorTransfer::Bt709);
    assert_eq!(selected.color().matrix, ColorMatrix::Bt709);
    assert_eq!(selected.color().range, ColorRange::Limited);
    assert_eq!(selected.rotation_degrees(), Some(-90));
    assert!(selected.hdr().mastering_display().is_some());
    assert!(selected.hdr().content_light().is_some());
    assert!(selected.hdr().dolby_vision().is_some());
    let audio = parsed.selected_audio().expect("selected audio");
    assert_eq!(audio.codec_display(), "aac");
    assert_eq!(audio.profile_display(), Some("LC"));
    assert_eq!(audio.sample_rate(), Some(48_000));
    assert_eq!(audio.channels(), Some(6));
    assert_eq!(audio.channel_layout(), Some("5.1"));
    assert_eq!(parsed.subtitle_streams().count(), 1);
    assert_eq!(parsed.chapters()[0].title(), Some("Part 1"));
}

#[test]
fn missing_values_remain_typed_unknown_and_average_rate_alone_is_never_constant() {
    let parsed = parse_probe_document(include_bytes!("fixtures/ffprobe/missing_unknown.json"))
        .expect("parse missing-value fixture");
    let video = parsed.selected_video().expect("fallback first video");

    assert_eq!(video.codec(), InputVideoCodec::OtherProbed);
    assert_eq!(video.codec_display(), "unknown");
    assert_eq!(video.profile(), VideoProfile::Unknown);
    assert_eq!(video.pixel_format(), PixelFormat::Unknown);
    assert_eq!(video.chroma(), ChromaSubsampling::Unknown);
    assert_eq!(video.frame_rate_class(), FrameRateClass::Unknown);

    let average_only = parse_probe_document(
        br#"{"streams":[{"index":0,"codec_type":"video","avg_frame_rate":"30/1"}]}"#,
    )
    .unwrap();
    assert_eq!(
        average_only.selected_video().unwrap().frame_rate_class(),
        FrameRateClass::Unknown
    );
}

#[test]
fn monochrome_pixel_format_infers_the_exact_known_bit_depth() {
    for (pixel_format, expected_format, expected_depth) in [
        ("gray", PixelFormat::Gray8, 8),
        ("gray10le", PixelFormat::Gray10le, 10),
    ] {
        let json = format!(
            r#"{{"streams":[{{"index":0,"codec_type":"video","codec_name":"h264","pix_fmt":"{pixel_format}"}}]}}"#
        );
        let document = parse_probe_document(json.as_bytes()).unwrap();
        let video = document.selected_video().unwrap();
        assert_eq!(video.pixel_format(), expected_format);
        assert_eq!(video.bit_depth(), Some(expected_depth));
        assert_eq!(video.chroma(), ChromaSubsampling::Monochrome);
    }
}

#[test]
fn malformed_deep_and_oversized_documents_fail_closed() {
    assert!(parse_probe_document(br#"{"streams":[}"#).is_err());
    let deep = format!("{}0{}", "[".repeat(40), "]".repeat(40));
    assert!(parse_probe_document(deep.as_bytes()).is_err());
    assert!(parse_probe_document(&vec![b' '; 8 * 1024 * 1024 + 1]).is_err());
    assert!(
        parse_probe_document(
            br#"{"streams":[{"index":0,"codec_type":"video","side_data_list":[
                {"side_data_type":"Content light level metadata","max_content":1000},
                {"side_data_type":"Content light level metadata","max_content":2000}
            ]}]}"#
        )
        .is_err()
    );
}

#[test]
fn typed_media_signature_changes_with_authorizing_video_fields() {
    let original = include_bytes!("fixtures/ffprobe/codec_matrix.json");
    let first = parse_probe_document(original).unwrap();
    let original_text = String::from_utf8(original.to_vec()).unwrap();
    for (name, from, to) in [
        (
            "codec",
            "\"codec_name\": \"h264\"",
            "\"codec_name\": \"hevc\"",
        ),
        (
            "sample entry",
            "\"codec_tag_string\": \"avc1\"",
            "\"codec_tag_string\": \"avc3\"",
        ),
        ("profile", "\"profile\": \"High\"", "\"profile\": \"Main\""),
        (
            "bit depth",
            "\"bits_per_raw_sample\": \"8\"",
            "\"bits_per_raw_sample\": \"10\"",
        ),
        (
            "pixel format",
            "\"pix_fmt\": \"yuv420p\"",
            "\"pix_fmt\": \"nv12\"",
        ),
        (
            "chroma",
            "\"pix_fmt\": \"yuv420p\"",
            "\"pix_fmt\": \"yuv422p\"",
        ),
        (
            "color",
            "\"color_primaries\": \"bt709\"",
            "\"color_primaries\": \"bt2020\"",
        ),
        (
            "frame rate",
            "\"r_frame_rate\": \"24000/1001\"",
            "\"r_frame_rate\": \"25/1\"",
        ),
        (
            "container",
            "\"format_name\": \"matroska,webm\"",
            "\"format_name\": \"mov,mp4,m4a,3gp,3g2,mj2\"",
        ),
    ] {
        let changed = original_text.replacen(from, to, 1);
        assert_ne!(changed, original_text, "fixture mutation exists: {name}");
        let second = parse_probe_document(changed.as_bytes()).unwrap();
        assert_ne!(
            first.media_signature(),
            second.media_signature(),
            "signature field: {name}"
        );
    }
}

#[test]
fn unknown_probe_text_does_not_fan_out_typed_media_signatures() {
    let first = parse_probe_document(
        br#"{
            "format":{"format_name":"future_container_a"},
            "streams":[{
                "index":4,"codec_type":"video","codec_name":"future_codec_a",
                "codec_tag_string":"future_tag_a","profile":"future_profile_a",
                "pix_fmt":"future_pixel_a","width":1920,"height":1080,
                "r_frame_rate":"24/1","avg_frame_rate":"24/1",
                "tags":{"language":"language_a"},"disposition":{"default":1}
            }],
            "chapters":[{"id":0,"tags":{"title":"title_a"}}]
        }"#,
    )
    .unwrap();
    let second = parse_probe_document(
        br#"{
            "format":{"format_name":"future_container_b"},
            "streams":[{
                "index":4,"codec_type":"video","codec_name":"future_codec_b",
                "codec_tag_string":"future_tag_b","profile":"future_profile_b",
                "pix_fmt":"future_pixel_b","width":1920,"height":1080,
                "r_frame_rate":"24/1","avg_frame_rate":"24/1",
                "tags":{"language":"language_b"},"disposition":{"default":1}
            }],
            "chapters":[{"id":0,"tags":{"title":"title_b"}}]
        }"#,
    )
    .unwrap();

    assert_eq!(first.media_signature(), second.media_signature());
}

#[test]
fn duplicate_stream_ids_fail_and_attached_pictures_are_not_selected_as_video() {
    assert!(
        parse_probe_document(
            br#"{"streams":[{"index":1,"codec_type":"video"},{"index":1,"codec_type":"audio"}]}"#
        )
        .is_err()
    );
    let document = r#"{"streams":[
            {"index":0,"codec_type":"video","codec_name":"mjpeg","disposition":{"default":1,"attached_pic":1}},
            {"index":2,"codec_type":"video","codec_name":"h264","tags":{"rotate":"180"},"disposition":{"default":0}}
        ],"chapters":[{"id":0,"tags":{"title":"日本語の章"}}]}"#;
    let parsed = parse_probe_document(document.as_bytes()).unwrap();
    assert_eq!(parsed.selected_video_stream(), Some(2));
    assert_eq!(
        parsed.selected_video().unwrap().rotation_degrees(),
        Some(180)
    );
}
