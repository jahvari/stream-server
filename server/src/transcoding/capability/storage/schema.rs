use serde::{Deserialize, Deserializer, Serialize, de::SeqAccess};
use std::{collections::BTreeMap, fmt, io::Write};

use crate::transcoding::inventory::RuntimeEvidenceId;

use super::super::{
    key::CapabilityKey,
    state::{EvidenceRecord, EvidenceTimestamp, PersistedEvidenceRecord, StateNow},
};

const CACHE_SCHEMA_VERSION: u16 = 1;
const CACHE_EVIDENCE_VERSION: u16 = 1;
pub(super) const MAX_CACHE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CACHE_RECORDS: usize = 3_072;
const MAX_WRITER_VERSION_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::transcoding::capability) enum CacheSchemaError {
    Bounds,
    IdentityMismatch,
    Invalid,
}

impl fmt::Display for CacheSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("cache_invalid")
    }
}

impl std::error::Error for CacheSchemaError {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EvidenceCacheDocument {
    schema_version: u16,
    evidence_version: u16,
    writer_server_version: String,
    written_at: u64,
    runtime_id: String,
    #[serde(deserialize_with = "deserialize_bounded_records")]
    records: Vec<PersistedEvidenceRecord>,
}

pub(in crate::transcoding::capability) fn encode_evidence_cache(
    runtime: &RuntimeEvidenceId,
    records: &BTreeMap<CapabilityKey, EvidenceRecord>,
    now: StateNow,
) -> Result<Vec<u8>, CacheSchemaError> {
    if records.len() > MAX_CACHE_RECORDS {
        return Err(CacheSchemaError::Bounds);
    }
    let mut persisted = Vec::with_capacity(records.len().min(MAX_CACHE_RECORDS));
    for (key, record) in records {
        if key != &record.key || key.runtime() != runtime || record.validate(now).is_err() {
            return Err(CacheSchemaError::Invalid);
        }
        if let Some(record) = PersistedEvidenceRecord::from_record(record) {
            persisted.push(record);
        }
    }
    let writer_server_version = env!("CARGO_PKG_VERSION").to_owned();
    if !safe_writer_version(&writer_server_version) {
        return Err(CacheSchemaError::Invalid);
    }
    let document = EvidenceCacheDocument {
        schema_version: CACHE_SCHEMA_VERSION,
        evidence_version: CACHE_EVIDENCE_VERSION,
        writer_server_version,
        written_at: now.wall().milliseconds(),
        runtime_id: runtime.persisted_hex(),
        records: persisted,
    };
    let mut writer = BoundedCacheWriter::new();
    serde_json::to_writer(&mut writer, &document).map_err(|error| {
        if error.is_io() {
            CacheSchemaError::Bounds
        } else {
            CacheSchemaError::Invalid
        }
    })?;
    Ok(writer.bytes)
}

pub(in crate::transcoding::capability) fn decode_evidence_cache(
    bytes: &[u8],
    expected_runtime: &RuntimeEvidenceId,
    now: StateNow,
) -> Result<BTreeMap<CapabilityKey, EvidenceRecord>, CacheSchemaError> {
    if bytes.len() > MAX_CACHE_BYTES {
        return Err(CacheSchemaError::Bounds);
    }
    let document: EvidenceCacheDocument =
        serde_json::from_slice(bytes).map_err(|_| CacheSchemaError::Invalid)?;
    if document.schema_version != CACHE_SCHEMA_VERSION
        || document.evidence_version != CACHE_EVIDENCE_VERSION
        || !safe_writer_version(&document.writer_server_version)
        || EvidenceTimestamp::new(document.written_at).is_err()
        || document.written_at > now.wall().milliseconds()
    {
        return Err(CacheSchemaError::Invalid);
    }
    let expected_runtime_hex = expected_runtime.persisted_hex();
    if document.runtime_id != expected_runtime_hex {
        return Err(CacheSchemaError::IdentityMismatch);
    }
    let mut records = BTreeMap::new();
    for persisted in document.records {
        if persisted.key.runtime_id() != expected_runtime_hex {
            return Err(CacheSchemaError::IdentityMismatch);
        }
        let record = persisted
            .into_record(now)
            .map_err(|_| CacheSchemaError::Invalid)?;
        if records.insert(record.key.clone(), record).is_some() {
            return Err(CacheSchemaError::Invalid);
        }
    }
    Ok(records)
}

fn deserialize_bounded_records<'de, D>(
    deserializer: D,
) -> Result<Vec<PersistedEvidenceRecord>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedRecordsVisitor;

    impl<'de> serde::de::Visitor<'de> for BoundedRecordsVisitor {
        type Value = Vec<PersistedEvidenceRecord>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("at most 3072 evidence records")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|hint| hint > MAX_CACHE_RECORDS)
            {
                return Err(serde::de::Error::custom("too many evidence records"));
            }
            let mut records =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX_CACHE_RECORDS));
            while records.len() < MAX_CACHE_RECORDS {
                let Some(record) = sequence.next_element()? else {
                    return Ok(records);
                };
                records.push(record);
            }
            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("too many evidence records"));
            }
            Ok(records)
        }
    }

    deserializer.deserialize_seq(BoundedRecordsVisitor)
}

fn safe_writer_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WRITER_VERSION_BYTES
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

struct BoundedCacheWriter {
    bytes: Vec<u8>,
}

impl BoundedCacheWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(64 * 1024),
        }
    }
}

impl Write for BoundedCacheWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let length = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .filter(|length| *length <= MAX_CACHE_BYTES)
            .ok_or_else(|| std::io::Error::other("cache serialization limit exceeded"))?;
        self.bytes.reserve_exact(length - self.bytes.len());
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
