//! Reads a baseline file (schema id `augenmass-baselines/0.1`) for
//! `audit --baseline` and `check --baseline`, and selects one entry of it.
//!
//! The format is documented in `docs/BASELINES.md`. Parsing is strict where
//! it decides a verdict: an unknown schema id, a duplicate entry id, an entry
//! without claims, a malformed path, an unknown (for example misspelt) member
//! or a duplicate member name is an error, never a file that loads with a
//! part of it ignored. Only the `info` members are free form.
//!
//! The engine type this module produces is
//! [`augenmass_core::typed_baseline::TypedBaseline`]; the comparison is the
//! engine's. This module does the file I/O the engine must not do.

use std::fmt;
use std::path::Path;

use anyhow::{anyhow, Result};
use augenmass_core::inspector::SD_JWT_VC_FORMATS;
use augenmass_core::regcert::{self, PathSeg, FORMAT_MSO_MDOC};
use augenmass_core::typed_baseline::{
    BaselineRow, EntryStatus, LegalSource, OneOfGroup, ReasonedRow, TypedBaseline, TypedCredential,
    SCHEMA_ID,
};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use url::Url;

use crate::commands::baselines::KNOWN_BASELINES;
use crate::render::printable;

/// A baseline file that passed every check, with all its entries.
#[derive(Debug, Clone)]
pub struct BaselineFile {
    /// The file name without any directory.
    pub file: String,
    pub entries: Vec<TypedBaseline>,
}

/// The file name of `path` without any directory, as every output names the
/// baseline file. Never the path as given, so that no directory of the
/// user's machine is printed.
pub fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "(baseline file)".to_string())
}

/// Read and check a baseline file. Every problem is an error that names the
/// file (by file name only), the place in the document and what is wrong.
pub fn load(path: &Path) -> Result<BaselineFile> {
    let file = file_name(path);
    let text = std::fs::read_to_string(path).map_err(|e| {
        anyhow!(
            "baseline file {}: cannot be read: {}",
            printable(&file),
            io_reason(&e)
        )
    })?;
    // The error may quote a member name or a value of the file: it is
    // printed on one line, without characters that act on a terminal.
    parse(&file, &text).map_err(|e| anyhow!("baseline file {}", printable(&format!("{file}: {e}"))))
}

/// The reason of an I/O error without the path (the operating system's text
/// does not carry it).
fn io_reason(e: &std::io::Error) -> String {
    e.to_string()
}

/// Check the text of a baseline file named `file`. The error is
/// "{where}: {what}".
pub fn parse(file: &str, text: &str) -> Result<BaselineFile, String> {
    let document = parse_without_duplicates(text).map_err(|e| format!("the document: {e}"))?;
    let top = members(&document, "the document", &["schema", "info", "entries"])?;

    match top.get("schema") {
        None => {
            return err(
                "schema",
                format!("missing; a baseline file states \"schema\": \"{SCHEMA_ID}\""),
            )
        }
        Some(Value::String(id)) if id == SCHEMA_ID => {}
        Some(other) => {
            return err(
                "schema",
                format!("unknown schema id {other}; this version reads only \"{SCHEMA_ID}\""),
            )
        }
    }

    let entries = match top.get("entries") {
        Some(Value::Array(entries)) if !entries.is_empty() => entries,
        _ => return err("entries", "must be a non-empty list of entries"),
    };
    let mut out: Vec<TypedBaseline> = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let parsed = parse_entry(file, entry, i)?;
        if out.iter().any(|e| e.id == parsed.id) {
            return err(
                &format!("entries[{i}]"),
                format!(
                    "duplicate entry id \"{}\"; an id names one entry of a file",
                    parsed.id
                ),
            );
        }
        out.push(parsed);
    }
    Ok(BaselineFile {
        file: file.to_string(),
        entries: out,
    })
}

impl BaselineFile {
    /// The entry a run judges against. `purpose` is the value of `--purpose`.
    /// It is optional only when the file has exactly one entry and that entry
    /// states no `applies_when`: an entry that holds only in a stated case is
    /// never applied without being named. The error is the text of a usage
    /// error.
    pub fn select(&self, purpose: Option<&str>) -> Result<TypedBaseline, String> {
        match purpose {
            Some(id) => self
                .entries
                .iter()
                .find(|e| e.id == id)
                .cloned()
                .ok_or_else(|| {
                    let ids: Vec<&str> = self.entries.iter().map(|e| e.id.as_str()).collect();
                    let mut message = format!(
                        "no entry '{id}' in baseline file {}. Entry ids: {}.",
                        printable(&self.file),
                        ids.join(", ")
                    );
                    if KNOWN_BASELINES.contains(&id) {
                        message.push_str(&format!(
                            " '{id}' is a built-in purpose; it is not used together with --baseline. Drop --baseline to use it."
                        ));
                    }
                    message
                }),
            None => match self.entries.as_slice() {
                [only] => match &only.applies_when {
                    None => Ok(only.clone()),
                    Some(case) => Err(format!(
                        "entry '{}' applies only when: {}. Name it with --purpose {} if that is the case you are checking.",
                        only.id,
                        printable(case),
                        only.id
                    )),
                },
                entries => {
                    let mut message = format!(
                        "baseline file {} has {} entries; name the one to judge against with --purpose <entry id>:",
                        printable(&self.file),
                        entries.len()
                    );
                    for entry in entries {
                        match &entry.applies_when {
                            Some(case) => message
                                .push_str(&format!(
                                    "\n  {}  applies when: {}",
                                    entry.id,
                                    printable(case)
                                )),
                            None => message.push_str(&format!("\n  {}", entry.id)),
                        }
                    }
                    Err(message)
                }
            },
        }
    }
}

// --- the checks ---------------------------------------------------------------

fn err<T>(at: &str, what: impl fmt::Display) -> Result<T, String> {
    Err(format!("{at}: {what}"))
}

/// The members of an object that may carry only the `known` member names. An
/// unknown member is an error: a misspelt machine-read member would
/// otherwise be skipped silently.
fn members<'a>(
    value: &'a Value,
    at: &str,
    known: &[&str],
) -> Result<&'a Map<String, Value>, String> {
    let Some(map) = value.as_object() else {
        return err(at, "must be an object");
    };
    for key in map.keys() {
        if !known.contains(&key.as_str()) {
            return err(
                at,
                format!(
                    "unknown member \"{key}\" (known members: {})",
                    known.join(", ")
                ),
            );
        }
    }
    Ok(map)
}

/// A required member that is a non-empty string.
fn text(map: &Map<String, Value>, at: &str, key: &str) -> Result<String, String> {
    match map.get(key) {
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(s.clone()),
        Some(_) => err(&format!("{at}.{key}"), "must be a non-empty string"),
        None => err(at, format!("\"{key}\" is missing")),
    }
}

/// An optional member that, when present, is a non-empty string.
fn optional_text(map: &Map<String, Value>, at: &str, key: &str) -> Result<Option<String>, String> {
    match map.get(key) {
        None => Ok(None),
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(Some(s.clone())),
        Some(_) => err(
            &format!("{at}.{key}"),
            "must be a non-empty string when present",
        ),
    }
}

/// An optional member that, when present, is a list.
fn optional_list<'a>(
    map: &'a Map<String, Value>,
    at: &str,
    key: &str,
) -> Result<&'a [Value], String> {
    match map.get(key) {
        None => Ok(&[]),
        Some(Value::Array(items)) => Ok(items),
        Some(_) => err(&format!("{at}.{key}"), "must be a list"),
    }
}

fn valid_entry_id(id: &str) -> bool {
    let mut chars = id.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn parse_entry(file: &str, entry: &Value, index: usize) -> Result<TypedBaseline, String> {
    let at = format!("entries[{index}]");
    let map = members(
        entry,
        &at,
        &[
            "id",
            "version",
            "status",
            "reviewer",
            "label",
            "applies_when",
            "claims",
            "one_of",
            "legal_sources",
            "info",
        ],
    )?;

    let id = text(map, &at, "id")?;
    if !valid_entry_id(&id) {
        return err(
            &format!("{at}.id"),
            format!("\"{id}\" is not an entry id: letters, digits, '.', '_' and '-', starting with a letter or a digit"),
        );
    }
    if KNOWN_BASELINES.contains(&id.as_str()) {
        return err(
            &format!("{at}.id"),
            format!("\"{id}\" is the id of a built-in purpose; choose another id, so that no id means two things"),
        );
    }
    let at = format!("entries[{index}] ({id})");

    let version = text(map, &at, "version")?;
    let status = match map.get("status") {
        Some(Value::String(s)) if s == "draft" => EntryStatus::Draft,
        Some(Value::String(s)) if s == "reviewed" => EntryStatus::Reviewed,
        Some(other) => {
            return err(
                &format!("{at}.status"),
                format!("must be \"draft\" or \"reviewed\", not {other}"),
            )
        }
        None => return err(&at, "\"status\" is missing (\"draft\" or \"reviewed\")"),
    };
    let reviewer = match map.get("reviewer") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.clone()),
        Some(_) => {
            return err(
                &format!("{at}.reviewer"),
                "must be null or a non-empty string",
            )
        }
    };
    if status == EntryStatus::Reviewed && reviewer.is_none() {
        return err(
            &format!("{at}.reviewer"),
            "an entry with the status \"reviewed\" names its reviewer",
        );
    }
    let label = optional_text(map, &at, "label")?;
    let applies_when = optional_text(map, &at, "applies_when")?;

    let blocks = match map.get("claims") {
        Some(Value::Array(blocks)) if !blocks.is_empty() => blocks,
        Some(_) => {
            return err(
                &format!("{at}.claims"),
                "must be a non-empty list of credential blocks",
            )
        }
        None => {
            return err(
                &at,
                "\"claims\" is missing; an entry without claims judges nothing",
            )
        }
    };
    let mut credentials: Vec<TypedCredential> = Vec::new();
    for (j, block) in blocks.iter().enumerate() {
        let block_at = format!("{at}.claims[{j}]");
        let parsed = parse_block(block, &block_at)?;
        for (k, earlier) in credentials.iter().enumerate() {
            let common = parsed
                .types()
                .into_iter()
                .find(|t| earlier.has_type(&parsed.format, t));
            if let Some(common) = common {
                return err(
                    &block_at,
                    format!(
                        "claims[{k}] already models the credential type {common} in format {}; one block per format and type",
                        parsed.format
                    ),
                );
            }
        }
        credentials.push(parsed);
    }
    if credentials.iter().all(|c| c.minimal.is_empty()) {
        return err(
            &format!("{at}.claims"),
            "no block has a \"minimal\" row; an entry states at least one minimal claim",
        );
    }

    let mut one_of: Vec<OneOfGroup> = Vec::new();
    for (g, group) in optional_list(map, &at, "one_of")?.iter().enumerate() {
        let group_at = format!("{at}.one_of[{g}]");
        let group_map = members(group, &group_at, &["id", "reason"])?;
        let group_id = text(group_map, &group_at, "id")?;
        if one_of.iter().any(|g| g.id == group_id) {
            return err(&group_at, format!("duplicate group id \"{group_id}\""));
        }
        one_of.push(OneOfGroup {
            id: group_id,
            reason: text(group_map, &group_at, "reason")?,
        });
    }
    let referenced: Vec<&str> = credentials
        .iter()
        .flat_map(|c| c.rows())
        .filter_map(|(_, _, _, group)| group)
        .collect();
    if let Some(unknown) = referenced
        .iter()
        .find(|name| !one_of.iter().any(|g| g.id == **name))
    {
        return err(
            &format!("{at}.claims"),
            format!("a row names the one_of group \"{unknown}\", which \"one_of\" of the entry does not declare"),
        );
    }
    for group in &one_of {
        let rows = referenced.iter().filter(|name| **name == group.id).count();
        if rows < 2 {
            return err(
                &format!("{at}.one_of"),
                format!(
                    "the group \"{}\" has {rows} row(s); a group of which a request may ask for one needs at least two",
                    group.id
                ),
            );
        }
    }

    let sources = match map.get("legal_sources") {
        Some(Value::Array(sources)) => sources,
        Some(_) => return err(&format!("{at}.legal_sources"), "must be a list"),
        None => {
            return err(
                &at,
                "\"legal_sources\" is missing (a list, which may be empty)",
            )
        }
    };
    let mut legal_sources = Vec::new();
    for (n, source) in sources.iter().enumerate() {
        legal_sources.push(parse_legal_source(
            source,
            &format!("{at}.legal_sources[{n}]"),
        )?);
    }

    Ok(TypedBaseline {
        file: file.to_string(),
        id,
        version,
        status,
        reviewer,
        label,
        applies_when,
        credentials,
        one_of,
        legal_sources,
    })
}

fn parse_block(block: &Value, at: &str) -> Result<TypedCredential, String> {
    let map = members(
        block,
        at,
        &[
            "format",
            "vct_values",
            "doctype_value",
            "minimal",
            "alternatives",
            "undecided",
        ],
    )?;
    let format = text(map, at, "format")?;
    let mdoc = format == FORMAT_MSO_MDOC;
    if !mdoc && !SD_JWT_VC_FORMATS.contains(&format.as_str()) {
        return err(
            &format!("{at}.format"),
            format!(
                "\"{format}\" is not a format a baseline can model: {}, {FORMAT_MSO_MDOC}",
                SD_JWT_VC_FORMATS.join(", ")
            ),
        );
    }

    let (vct_values, doctype_value) = if mdoc {
        if map.contains_key("vct_values") {
            return err(
                at,
                "an mso_mdoc block names its type with \"doctype_value\", not \"vct_values\"",
            );
        }
        (Vec::new(), Some(text(map, at, "doctype_value")?))
    } else {
        if map.contains_key("doctype_value") {
            return err(
                at,
                format!(
                    "a {format} block names its types with \"vct_values\", not \"doctype_value\""
                ),
            );
        }
        let values = match map.get("vct_values") {
            Some(Value::Array(values)) if !values.is_empty() => values,
            _ => {
                return err(
                    &format!("{at}.vct_values"),
                    "must be a non-empty list of credential types (vct)",
                )
            }
        };
        let mut vcts: Vec<String> = Vec::new();
        for value in values {
            match value {
                Value::String(s) if !s.trim().is_empty() && !vcts.contains(s) => {
                    vcts.push(s.clone())
                }
                _ => {
                    return err(
                        &format!("{at}.vct_values"),
                        "must hold non-empty strings, each once",
                    )
                }
            }
        }
        (vcts, None)
    };

    let mut minimal = Vec::new();
    for (k, row) in optional_list(map, at, "minimal")?.iter().enumerate() {
        let row_at = format!("{at}.minimal[{k}]");
        let row_map = members(row, &row_at, &["path", "one_of"])?;
        minimal.push(BaselineRow {
            path: parse_path(row_map, &row_at, &format)?,
            one_of: optional_text(row_map, &row_at, "one_of")?,
        });
    }
    let reasoned = |key: &str| -> Result<Vec<ReasonedRow>, String> {
        let mut rows = Vec::new();
        for (k, row) in optional_list(map, at, key)?.iter().enumerate() {
            let row_at = format!("{at}.{key}[{k}]");
            let row_map = members(row, &row_at, &["path", "one_of", "reason"])?;
            rows.push(ReasonedRow {
                path: parse_path(row_map, &row_at, &format)?,
                one_of: optional_text(row_map, &row_at, "one_of")?,
                reason: text(row_map, &row_at, "reason")?,
            });
        }
        Ok(rows)
    };
    let credential = TypedCredential {
        alternatives: reasoned("alternatives")?,
        undecided: reasoned("undecided")?,
        format,
        vct_values,
        doctype_value,
        minimal,
    };

    let rows = credential.rows();
    if rows.is_empty() {
        return err(
            at,
            "the block has no row in \"minimal\", \"alternatives\" or \"undecided\"",
        );
    }
    // No two rows of a block may overlap, in one list or across lists: a
    // requested path then matches at most one row, and no result depends on
    // the order of the lists or of the rows. Two rows overlap when some path
    // is covered by both. That includes rows of which neither covers the
    // other, such as ["a", null, 0] and ["a", 0, null].
    for (i, (_, _, a, _)) in rows.iter().enumerate() {
        for (_, _, b, _) in &rows[i + 1..] {
            if let Some(common) = regcert::common_covered_path(a, b, mdoc) {
                return err(
                    at,
                    format!(
                        "the rows {} and {} overlap (both cover the path {}); a requested claim must match at most one row of a block",
                        path_text(a),
                        path_text(b),
                        path_text(&common)
                    ),
                );
            }
        }
    }
    Ok(credential)
}

/// The `path` of a row: a claims path pointer with typed segments.
fn parse_path(row: &Map<String, Value>, at: &str, format: &str) -> Result<Vec<PathSeg>, String> {
    let at = format!("{at}.path");
    let Some(value) = row.get("path") else {
        return err(&at, "is missing");
    };
    let Some(path) = regcert::parse_claim_path(value) else {
        return err(
            &at,
            "must be a non-empty array of strings, nulls and non-negative integers (a claims path pointer)",
        );
    };
    if path
        .iter()
        .any(|seg| matches!(seg, PathSeg::Key(key) if key.is_empty()))
    {
        return err(&at, "has an empty string segment");
    }
    if !regcert::valid_claim_path(format, &path) {
        return err(
            &at,
            "an mso_mdoc path is exactly two strings: [namespace, data element]",
        );
    }
    Ok(path)
}

/// A path as the JSON array it was read from.
pub fn path_text(path: &[PathSeg]) -> String {
    let segs: Vec<String> = path
        .iter()
        .map(|seg| serde_json::to_string(seg).unwrap_or_else(|_| seg.display()))
        .collect();
    format!("[{}]", segs.join(", "))
}

fn parse_legal_source(source: &Value, at: &str) -> Result<LegalSource, String> {
    let map = members(
        source,
        at,
        &["instrument", "locator", "quote", "url", "retrieved", "note"],
    )?;
    let url = optional_text(map, at, "url")?;
    if let Some(url) = &url {
        let http = Url::parse(url).is_ok_and(|u| matches!(u.scheme(), "http" | "https"));
        if !http {
            return err(&format!("{at}.url"), "must be an http or https URL");
        }
    }
    Ok(LegalSource {
        instrument: text(map, at, "instrument")?,
        locator: text(map, at, "locator")?,
        quote: text(map, at, "quote")?,
        url,
        retrieved: optional_text(map, at, "retrieved")?,
        note: optional_text(map, at, "note")?,
    })
}

// --- JSON without duplicate member names --------------------------------------

/// Parse JSON into a value, rejecting an object that carries a member name
/// twice. `serde_json` keeps the last of two members silently, which would
/// let a second `"status"` or `"minimal"` replace the first unseen.
fn parse_without_duplicates(text: &str) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = NoDuplicates.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

struct NoDuplicates;

impl<'de> DeserializeSeed<'de> for NoDuplicates {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for NoDuplicates {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Number::from_f64(v).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(NoDuplicates)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "the member \"{key}\" occurs twice in one object"
                )));
            }
            let value = map.next_value_seed(NoDuplicates)?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const EXAMPLE: &str = include_str!("../examples/baselines-example.json");

    /// A small valid file: one entry, the German PID as SD-JWT VC and as
    /// mdoc, both rows in one group. Every name is invented.
    fn valid() -> Value {
        json!({
            "schema": "augenmass-baselines/0.1",
            "entries": [{
                "id": "example.test.age",
                "version": "0.1",
                "status": "draft",
                "reviewer": null,
                "claims": [
                    {
                        "format": "dc+sd-jwt",
                        "vct_values": ["urn:eudi:pid:de:1"],
                        "minimal": [{ "path": ["age_equal_or_over", "18"], "one_of": "age-claim" }]
                    },
                    {
                        "format": "mso_mdoc",
                        "doctype_value": "eu.europa.ec.eudi.pid.1",
                        "minimal": [{ "path": ["eu.europa.ec.eudi.pid.de.1", "age_over_18"], "one_of": "age-claim" }],
                        "alternatives": [{ "path": ["eu.europa.ec.eudi.pid.1", "age_over_18"], "one_of": "age-claim", "reason": "invented reason" }]
                    }
                ],
                "one_of": [{ "id": "age-claim", "reason": "invented rule" }],
                "legal_sources": [{
                    "instrument": "Invented Example Ordinance (not a real law)",
                    "locator": "section 1 (invented)",
                    "quote": "Invented for this test."
                }]
            }]
        })
    }

    fn load_value(v: &Value) -> Result<BaselineFile, String> {
        parse("test.json", &v.to_string())
    }

    /// The error of a file that is [`valid`] after `change`.
    fn rejected(change: impl FnOnce(&mut Value)) -> String {
        let mut v = valid();
        change(&mut v);
        match load_value(&v) {
            Ok(_) => panic!("the file loaded: {v}"),
            Err(e) => e,
        }
    }

    fn entry(v: &mut Value) -> &mut Value {
        &mut v["entries"][0]
    }

    fn sd_jwt(v: &mut Value) -> &mut Value {
        &mut v["entries"][0]["claims"][0]
    }

    fn mdoc(v: &mut Value) -> &mut Value {
        &mut v["entries"][0]["claims"][1]
    }

    fn remove(v: &mut Value, key: &str) {
        v.as_object_mut().expect("object").remove(key);
    }

    #[test]
    fn valid_file_and_the_example_file_load() {
        let file = load_value(&valid()).expect("valid");
        assert_eq!(file.file, "test.json");
        assert_eq!(file.entries.len(), 1);
        let e = &file.entries[0];
        assert_eq!(e.id, "example.test.age");
        assert_eq!(e.status, EntryStatus::Draft);
        assert_eq!(e.reviewer, None);
        assert_eq!(e.credentials.len(), 2);
        assert_eq!(
            e.credentials[0].minimal[0].path,
            vec![
                PathSeg::Key("age_equal_or_over".to_string()),
                PathSeg::Key("18".to_string())
            ]
        );
        assert_eq!(e.credentials[1].types(), vec!["eu.europa.ec.eudi.pid.1"]);
        assert_eq!(e.legal_sources.len(), 1);

        let example = parse("baselines-example.json", EXAMPLE).expect("example file");
        let ids: Vec<&str> = example.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "example.wine-shop.age-check.wine",
                "example.wine-shop.age-check.spirits",
                "example.wine-shop.loyalty-card",
            ]
        );
        for e in &example.entries {
            assert_eq!(e.status, EntryStatus::Draft);
            assert_eq!(e.file, "baselines-example.json");
            for source in &e.legal_sources {
                assert!(source.instrument.contains("Invented"), "{source:?}");
                assert!(source.instrument.contains("not a real law"), "{source:?}");
                assert!(source.url.is_none());
            }
        }
        // Three blocks, the third a second credential type of one format.
        assert_eq!(example.entries[0].credentials.len(), 3);
        assert_eq!(
            example.entries[0].credentials[2].types(),
            vec!["eu.europa.ec.av.1"]
        );
    }

    #[test]
    fn info_is_free_form_at_both_levels() {
        let mut v = valid();
        v["info"] = json!({ "any": ["thing", 1, null, { "status": "ignored" }] });
        entry(&mut v)["info"] = json!("free text");
        load_value(&v).expect("info is never read");
    }

    #[test]
    fn schema_id_is_required_and_exact() {
        let e = rejected(|v| v["schema"] = json!("augenmass-baselines/0.2"));
        assert_eq!(
            e,
            "schema: unknown schema id \"augenmass-baselines/0.2\"; this version reads only \"augenmass-baselines/0.1\""
        );
        let e = rejected(|v| remove(v, "schema"));
        assert!(e.starts_with("schema: missing"), "{e}");
        let e = rejected(|v| v["schema"] = json!(0.1));
        assert!(e.starts_with("schema: unknown schema id"), "{e}");
    }

    #[test]
    fn document_must_be_a_json_object_without_duplicate_members() {
        assert!(parse("t.json", "not json")
            .unwrap_err()
            .starts_with("the document: "));
        assert_eq!(
            parse("t.json", "[]").unwrap_err(),
            "the document: must be an object"
        );
        // serde_json would keep the second "status" silently.
        let text = valid().to_string().replace(
            "\"status\":\"draft\"",
            "\"status\":\"reviewed\",\"status\":\"draft\"",
        );
        assert_ne!(text, valid().to_string());
        let e = parse("t.json", &text).unwrap_err();
        assert!(
            e.contains("the member \"status\" occurs twice in one object"),
            "{e}"
        );
        // Also inside the free-form info.
        let e = parse(
            "t.json",
            r#"{"schema":"augenmass-baselines/0.1","info":{"a":1,"a":2},"entries":[]}"#,
        )
        .unwrap_err();
        assert!(e.contains("occurs twice"), "{e}");
        // Trailing content after the document.
        assert!(parse("t.json", &format!("{} {{}}", valid())).is_err());
    }

    #[test]
    fn unknown_members_are_rejected_at_every_level() {
        type Change = Box<dyn FnOnce(&mut Value)>;
        let cases: Vec<(&str, Change)> = vec![
            ("the document", Box::new(|v| v["entrys"] = json!([]))),
            (
                "entries[0]",
                Box::new(|v| entry(v)["statuss"] = json!("draft")),
            ),
            (
                "entries[0] (example.test.age).claims[0]",
                Box::new(|v| sd_jwt(v)["minimial"] = json!([])),
            ),
            (
                "entries[0] (example.test.age).claims[1]",
                Box::new(|v| mdoc(v)["doctype"] = json!("x")),
            ),
            (
                "entries[0] (example.test.age).claims[0].minimal[0]",
                Box::new(|v| sd_jwt(v)["minimal"][0]["oneof"] = json!("age-claim")),
            ),
            (
                "entries[0] (example.test.age).claims[0].minimal[0]",
                Box::new(|v| sd_jwt(v)["minimal"][0]["condition"] = json!("only on Sundays")),
            ),
            (
                "entries[0] (example.test.age).claims[0].minimal[0]",
                Box::new(|v| sd_jwt(v)["minimal"][0]["when"] = json!("the basket holds wine")),
            ),
            (
                "entries[0] (example.test.age).claims[1].alternatives[0]",
                Box::new(|v| mdoc(v)["alternatives"][0]["reasons"] = json!("x")),
            ),
            (
                "entries[0] (example.test.age).one_of[0]",
                Box::new(|v| entry(v)["one_of"][0]["rows"] = json!([])),
            ),
            (
                "entries[0] (example.test.age).legal_sources[0]",
                Box::new(|v| entry(v)["legal_sources"][0]["saved_copy"] = json!("x")),
            ),
        ];
        for (at, change) in cases {
            let e = rejected(change);
            assert!(
                e.starts_with(&format!("{at}: unknown member \"")),
                "{at}: {e}"
            );
        }
        // A misspelt machine field never loads as a file without that field.
        let e = rejected(|v| {
            let block = sd_jwt(v);
            let vcts = block["vct_values"].take();
            remove(block, "vct_values");
            block["vct_value"] = vcts;
        });
        assert!(
            e.contains("unknown member \"vct_value\" (known members: format, vct_values, doctype_value, minimal, alternatives, undecided)"),
            "{e}"
        );
    }

    #[test]
    fn entries_and_ids_are_checked() {
        assert_eq!(
            rejected(|v| v["entries"] = json!([])),
            "entries: must be a non-empty list of entries"
        );
        assert!(rejected(|v| remove(v, "entries")).starts_with("entries: "));
        assert!(rejected(|v| v["entries"] = json!({})).starts_with("entries: "));

        let e = rejected(|v| {
            let copy = entry(v).clone();
            v["entries"].as_array_mut().expect("entries").push(copy);
        });
        assert_eq!(
            e,
            "entries[1]: duplicate entry id \"example.test.age\"; an id names one entry of a file"
        );

        for id in ["", " ", "-leading", "has space", "umlaut-ä", "a/b"] {
            let e = rejected(|v| entry(v)["id"] = json!(id));
            assert!(e.starts_with("entries[0]"), "{id}: {e}");
        }
        assert!(rejected(|v| entry(v)["id"] = json!(7)).contains("non-empty string"));
        assert!(rejected(|v| remove(entry(v), "id")).contains("\"id\" is missing"));

        for id in KNOWN_BASELINES {
            let e = rejected(|v| entry(v)["id"] = json!(id));
            assert!(e.contains("is the id of a built-in purpose"), "{id}: {e}");
        }
    }

    #[test]
    fn version_status_reviewer_and_applies_when_are_checked() {
        assert!(rejected(|v| remove(entry(v), "version")).contains("\"version\" is missing"));
        assert!(rejected(|v| entry(v)["version"] = json!("")).contains("non-empty string"));
        assert!(rejected(|v| entry(v)["version"] = json!(1)).contains("non-empty string"));

        let e = rejected(|v| entry(v)["status"] = json!("final"));
        assert_eq!(
            e,
            "entries[0] (example.test.age).status: must be \"draft\" or \"reviewed\", not \"final\""
        );
        assert!(rejected(|v| entry(v)["status"] = json!("draft-unreviewed")).contains("status"));
        assert!(rejected(|v| remove(entry(v), "status")).contains("\"status\" is missing"));

        let e = rejected(|v| entry(v)["status"] = json!("reviewed"));
        assert_eq!(
            e,
            "entries[0] (example.test.age).reviewer: an entry with the status \"reviewed\" names its reviewer"
        );
        assert!(rejected(|v| entry(v)["reviewer"] = json!("")).contains("reviewer"));
        assert!(rejected(|v| entry(v)["reviewer"] = json!(false)).contains("reviewer"));

        let mut v = valid();
        entry(&mut v)["status"] = json!("reviewed");
        entry(&mut v)["reviewer"] = json!("Example Reviewer");
        let file = load_value(&v).expect("reviewed entry");
        assert_eq!(file.entries[0].status, EntryStatus::Reviewed);
        assert_eq!(
            file.entries[0].reviewer.as_deref(),
            Some("Example Reviewer")
        );
        // A draft may name a reviewer; the member may also be absent.
        let mut v = valid();
        remove(entry(&mut v), "reviewer");
        load_value(&v).expect("reviewer absent");

        for bad in [json!(""), json!(null), json!(["a"]), json!(true)] {
            let e = rejected(|v| entry(v)["applies_when"] = bad.clone());
            assert!(e.contains("applies_when"), "{bad}: {e}");
        }
        assert!(rejected(|v| entry(v)["label"] = json!("")).contains("label"));
    }

    #[test]
    fn an_entry_needs_claims_blocks_and_a_minimal_row() {
        let e = rejected(|v| remove(entry(v), "claims"));
        assert_eq!(
            e,
            "entries[0] (example.test.age): \"claims\" is missing; an entry without claims judges nothing"
        );
        assert!(rejected(|v| entry(v)["claims"] = json!([])).contains("non-empty list"));
        // The first sketch of the format: a map keyed by format.
        let e = rejected(|v| {
            entry(v)["claims"] =
                json!({ "dc+sd-jwt": { "minimal": [["age_equal_or_over", "18"]] } })
        });
        assert!(
            e.contains("claims: must be a non-empty list of credential blocks"),
            "{e}"
        );

        // A block without any row.
        let e = rejected(|v| {
            entry(v)["claims"]
                .as_array_mut()
                .expect("claims")
                .push(json!({ "format": "dc+sd-jwt", "vct_values": ["urn:example:other:1"] }));
        });
        assert!(e.contains("the block has no row"), "{e}");

        // An entry with alternatives only.
        let e = rejected(|v| {
            entry(v)["claims"] = json!([{
                "format": "mso_mdoc",
                "doctype_value": "eu.europa.ec.av.1",
                "alternatives": [{ "path": ["eu.europa.ec.av.1", "age_over_18"], "reason": "x" }]
            }]);
            entry(v)["one_of"] = json!([]);
        });
        assert!(e.contains("no block has a \"minimal\" row"), "{e}");
    }

    #[test]
    fn formats_and_types_are_checked() {
        let e = rejected(|v| sd_jwt(v)["format"] = json!("jwt_vc_json"));
        assert!(
            e.contains("\"jwt_vc_json\" is not a format a baseline can model: dc+sd-jwt, vc+sd-jwt, mso_mdoc"),
            "{e}"
        );
        assert!(rejected(|v| remove(sd_jwt(v), "format")).contains("\"format\" is missing"));

        assert!(rejected(|v| remove(sd_jwt(v), "vct_values")).contains("vct_values"));
        for bad in [
            json!([]),
            json!("urn:eudi:pid:de:1"),
            json!([""]),
            json!([1]),
            json!(["a", "a"]),
        ] {
            let e = rejected(|v| sd_jwt(v)["vct_values"] = bad.clone());
            assert!(e.contains("vct_values"), "{bad}: {e}");
        }
        let e = rejected(|v| sd_jwt(v)["doctype_value"] = json!("eu.europa.ec.eudi.pid.1"));
        assert!(e.contains("names its types with \"vct_values\""), "{e}");

        let e = rejected(|v| mdoc(v)["vct_values"] = json!(["urn:eudi:pid:de:1"]));
        assert!(e.contains("names its type with \"doctype_value\""), "{e}");
        assert!(rejected(|v| remove(mdoc(v), "doctype_value")).contains("doctype_value"));
        assert!(rejected(|v| mdoc(v)["doctype_value"] = json!("")).contains("doctype_value"));
        assert!(rejected(|v| mdoc(v)["doctype_value"] = json!(["x"])).contains("doctype_value"));

        // Two blocks with the same format and a common type.
        let e = rejected(|v| {
            entry(v)["claims"]
                .as_array_mut()
                .expect("claims")
                .push(json!({
                    "format": "dc+sd-jwt",
                    "vct_values": ["urn:example:other:1", "urn:eudi:pid:de:1"],
                    "minimal": [{ "path": ["given_name"] }]
                }));
        });
        assert!(
            e.contains("claims[0] already models the credential type urn:eudi:pid:de:1 in format dc+sd-jwt"),
            "{e}"
        );
        // The same type in another format is another block.
        let mut v = valid();
        entry(&mut v)["claims"]
            .as_array_mut()
            .expect("claims")
            .push(json!({
                "format": "vc+sd-jwt",
                "vct_values": ["urn:eudi:pid:de:1"],
                "minimal": [{ "path": ["age_equal_or_over", "18"] }]
            }));
        load_value(&v).expect("vc+sd-jwt block");
    }

    #[test]
    fn malformed_paths_are_rejected() {
        let bad_paths = [
            json!("age_equal_or_over.18"),
            json!([]),
            json!(["age_equal_or_over", -1]),
            json!(["age_equal_or_over", 1.5]),
            json!(["age_equal_or_over", true]),
            json!(["age_equal_or_over", {}]),
            json!(["age_equal_or_over", ["18"]]),
            json!(["age_equal_or_over", ""]),
            json!(null),
        ];
        for bad in bad_paths {
            let e = rejected(|v| sd_jwt(v)["minimal"][0]["path"] = bad.clone());
            assert!(
                e.starts_with("entries[0] (example.test.age).claims[0].minimal[0].path: "),
                "{bad}: {e}"
            );
        }
        let e = rejected(|v| remove(&mut sd_jwt(v)["minimal"][0], "path"));
        assert!(e.ends_with("minimal[0].path: is missing"), "{e}");
        // A bare path array instead of a row object (the first sketch).
        let e = rejected(|v| sd_jwt(v)["minimal"][0] = json!(["age_equal_or_over", "18"]));
        assert!(e.ends_with("minimal[0]: must be an object"), "{e}");

        // mso_mdoc: exactly two strings.
        for bad in [
            json!(["eu.europa.ec.eudi.pid.de.1", "age_over_18", "x"]),
            json!(["eu.europa.ec.eudi.pid.de.1"]),
            json!(["eu.europa.ec.eudi.pid.de.1", 0]),
            json!(["eu.europa.ec.eudi.pid.de.1", null]),
        ] {
            let e = rejected(|v| mdoc(v)["minimal"][0]["path"] = bad.clone());
            assert!(
                e.contains("an mso_mdoc path is exactly two strings"),
                "{bad}: {e}"
            );
        }

        // Typed segments load as written.
        let mut v = valid();
        sd_jwt(&mut v)["minimal"]
            .as_array_mut()
            .expect("minimal")
            .push(json!({ "path": ["nationalities", null] }));
        sd_jwt(&mut v)["minimal"]
            .as_array_mut()
            .expect("minimal")
            .push(json!({ "path": ["codes", 3] }));
        let file = load_value(&v).expect("typed paths");
        assert_eq!(
            file.entries[0].credentials[0].minimal[1].path,
            vec![PathSeg::Key("nationalities".to_string()), PathSeg::All]
        );
        assert_eq!(
            file.entries[0].credentials[0].minimal[2].path,
            vec![PathSeg::Key("codes".to_string()), PathSeg::Index(3)]
        );
    }

    /// A file with one SD-JWT block of an invented credential type holding
    /// the given rows.
    fn with_rows(minimal: Value, alternatives: Value, undecided: Value) -> Value {
        let mut v = valid();
        entry(&mut v)["claims"] = json!([{
            "format": "dc+sd-jwt",
            "vct_values": ["urn:example:loyalty:1"],
            "minimal": minimal,
            "alternatives": alternatives,
            "undecided": undecided,
        }]);
        entry(&mut v)["one_of"] = json!([]);
        v
    }

    #[test]
    fn overlapping_rows_of_one_block_are_rejected() {
        let row = |p: Value| json!({ "path": p });
        let why = |p: Value| json!({ "path": p, "reason": "invented reason" });
        let overlapping = [
            // The same path in minimal twice.
            with_rows(
                json!([row(json!(["a"])), row(json!(["a"]))]),
                json!([]),
                json!([]),
            ),
            // The same path in minimal and in alternatives.
            with_rows(
                json!([row(json!(["a"]))]),
                json!([why(json!(["a"]))]),
                json!([]),
            ),
            // A row covers a row of another list.
            with_rows(
                json!([row(json!(["profile"]))]),
                json!([]),
                json!([why(json!(["profile", "sensitive"]))]),
            ),
            with_rows(
                json!([row(json!(["profile"]))]),
                json!([why(json!(["profile", "name"]))]),
                json!([]),
            ),
            with_rows(
                json!([row(json!(["profile", "name"]))]),
                json!([]),
                json!([why(json!(["profile"]))]),
            ),
            // null covers an index.
            with_rows(
                json!([
                    row(json!(["nationalities", null])),
                    row(json!(["nationalities", 0]))
                ]),
                json!([]),
                json!([]),
            ),
        ];
        for file in overlapping {
            let e = load_value(&file).expect_err("overlap");
            assert!(e.contains("overlap"), "{e}");
        }

        // An ungrouped ancestor of a grouped row.
        let mut v = with_rows(
            json!([
                { "path": ["age_equal_or_over"] },
                { "path": ["age_equal_or_over", "18"], "one_of": "g" },
                { "path": ["other"], "one_of": "g" },
            ]),
            json!([]),
            json!([]),
        );
        entry(&mut v)["one_of"] = json!([{ "id": "g", "reason": "invented" }]);
        let e = load_value(&v).expect_err("overlap");
        assert!(
            e.contains(
                "the rows [\"age_equal_or_over\"] and [\"age_equal_or_over\", \"18\"] overlap"
            ),
            "{e}"
        );

        // Crossed wildcards: neither row covers the other, but both cover
        // ["a", 0, 0]. Without the rejection the first row in file order
        // would win, and an ungrouped first row would hide the group of the
        // second.
        for (first, second) in [
            (json!(["a", null, 0]), json!(["a", 0, null])),
            (json!(["a", 0, null]), json!(["a", null, 0])),
        ] {
            let mut v = with_rows(
                json!([
                    { "path": first },
                    { "path": second, "one_of": "g" },
                    { "path": ["b"], "one_of": "g" },
                ]),
                json!([]),
                json!([]),
            );
            entry(&mut v)["one_of"] = json!([{ "id": "g", "reason": "invented" }]);
            let e = load_value(&v).expect_err("crossed wildcards");
            assert!(
                e.contains("overlap (both cover the path [\"a\", 0, 0])"),
                "{e}"
            );
        }
        let e = load_value(&with_rows(
            json!([row(json!(["a", null, "b", 0]))]),
            json!([]),
            json!([why(json!(["a", 0, "b", null]))]),
        ))
        .expect_err("crossed wildcards across lists");
        assert!(
            e.contains("the rows [\"a\", null, \"b\", 0] and [\"a\", 0, \"b\", null] overlap (both cover the path [\"a\", 0, \"b\", 0])"),
            "{e}"
        );
        // Wildcards that cannot meet: different integers at one position.
        load_value(&with_rows(
            json!([row(json!(["a", 0, null])), row(json!(["a", 1, 0]))]),
            json!([]),
            json!([]),
        ))
        .expect("different indices");

        // Not overlaps: a string and an integer segment, siblings, and the
        // same path in two blocks.
        load_value(&with_rows(
            json!([row(json!(["a", "18"])), row(json!(["a", 18]))]),
            json!([]),
            json!([]),
        ))
        .expect("\"18\" and 18 differ");
        load_value(&with_rows(
            json!([row(json!(["a", "b"]))]),
            json!([why(json!(["a", "c"]))]),
            json!([]),
        ))
        .expect("siblings");
        let mut v = valid();
        entry(&mut v)["claims"]
            .as_array_mut()
            .expect("claims")
            .push(json!({
                "format": "dc+sd-jwt",
                "vct_values": ["urn:eudi:pid:1"],
                "minimal": [{ "path": ["age_equal_or_over", "18"] }]
            }));
        load_value(&v).expect("the same path in two blocks");

        // mso_mdoc: only equal paths overlap.
        let e = rejected(|v| {
            mdoc(v)["alternatives"][0]["path"] =
                json!(["eu.europa.ec.eudi.pid.de.1", "age_over_18"])
        });
        assert!(e.contains("overlap"), "{e}");
    }

    #[test]
    fn reasons_and_groups_are_checked() {
        let e = rejected(|v| remove(&mut mdoc(v)["alternatives"][0], "reason"));
        assert!(e.contains("alternatives[0]: \"reason\" is missing"), "{e}");
        assert!(rejected(|v| mdoc(v)["alternatives"][0]["reason"] = json!("")).contains("reason"));
        let e = rejected(|v| {
            mdoc(v)["undecided"] = json!([{ "path": ["eu.europa.ec.eudi.pid.de.1", "status"] }])
        });
        assert!(e.contains("undecided[0]: \"reason\" is missing"), "{e}");
        // A minimal row carries no reason.
        let e = rejected(|v| sd_jwt(v)["minimal"][0]["reason"] = json!("x"));
        assert!(e.contains("unknown member \"reason\""), "{e}");

        let e = rejected(|v| sd_jwt(v)["minimal"][0]["one_of"] = json!("no-such-group"));
        assert!(
            e.contains("a row names the one_of group \"no-such-group\", which \"one_of\" of the entry does not declare"),
            "{e}"
        );
        let e = rejected(|v| remove(entry(v), "one_of"));
        assert!(e.contains("does not declare"), "{e}");

        let e = rejected(|v| {
            remove(&mut sd_jwt(v)["minimal"][0], "one_of");
            remove(&mut mdoc(v)["minimal"][0], "one_of");
        });
        assert!(e.contains("the group \"age-claim\" has 1 row(s)"), "{e}");

        let e = rejected(|v| {
            let group = entry(v)["one_of"][0].clone();
            entry(v)["one_of"]
                .as_array_mut()
                .expect("one_of")
                .push(group);
        });
        assert!(e.contains("duplicate group id \"age-claim\""), "{e}");
        assert!(rejected(|v| remove(&mut entry(v)["one_of"][0], "reason")).contains("reason"));
        assert!(rejected(|v| entry(v)["one_of"] = json!({})).contains("one_of: must be a list"));
    }

    #[test]
    fn legal_sources_are_checked() {
        assert!(rejected(|v| remove(entry(v), "legal_sources")).contains("legal_sources"));
        assert!(rejected(|v| entry(v)["legal_sources"] = json!({})).contains("must be a list"));
        for key in ["instrument", "locator", "quote"] {
            let e = rejected(|v| remove(&mut entry(v)["legal_sources"][0], key));
            assert!(e.contains(&format!("\"{key}\" is missing")), "{key}: {e}");
            let e = rejected(|v| entry(v)["legal_sources"][0][key] = json!(""));
            assert!(e.contains(key), "{key}: {e}");
        }
        for url in [
            "ftp://example.org/law",
            "example.org/law",
            "javascript:alert(1)",
            "",
        ] {
            let e = rejected(|v| entry(v)["legal_sources"][0]["url"] = json!(url));
            assert!(e.contains("legal_sources[0].url"), "{url}: {e}");
        }
        let mut v = valid();
        entry(&mut v)["legal_sources"][0]["url"] = json!("https://example.org/law");
        entry(&mut v)["legal_sources"][0]["retrieved"] = json!("2026-11-13");
        entry(&mut v)["legal_sources"][0]["note"] = json!("invented");
        let file = load_value(&v).expect("source with url");
        assert_eq!(
            file.entries[0].legal_sources[0].url.as_deref(),
            Some("https://example.org/law")
        );
        // An empty list is allowed.
        let mut v = valid();
        entry(&mut v)["legal_sources"] = json!([]);
        load_value(&v).expect("no sources");
    }

    #[test]
    fn selection_with_one_entry() {
        let file = load_value(&valid()).expect("valid");
        assert_eq!(
            file.select(None).expect("the one entry").id,
            "example.test.age"
        );
        assert_eq!(
            file.select(Some("example.test.age")).expect("by id").id,
            "example.test.age"
        );

        let e = file.select(Some("no.such.entry")).unwrap_err();
        assert_eq!(
            e,
            "no entry 'no.such.entry' in baseline file test.json. Entry ids: example.test.age."
        );
        let e = file.select(Some("age_gate_18")).unwrap_err();
        assert_eq!(
            e,
            "no entry 'age_gate_18' in baseline file test.json. Entry ids: example.test.age. 'age_gate_18' is a built-in purpose; it is not used together with --baseline. Drop --baseline to use it."
        );

        // An entry that states a case is never applied without being named.
        let mut v = valid();
        entry(&mut v)["applies_when"] = json!("the order holds wine");
        let file = load_value(&v).expect("valid");
        assert_eq!(
            file.select(None).unwrap_err(),
            "entry 'example.test.age' applies only when: the order holds wine. Name it with --purpose example.test.age if that is the case you are checking."
        );
        assert!(file.select(Some("example.test.age")).is_ok());
    }

    #[test]
    fn selection_with_several_entries() {
        let file = parse("baselines-example.json", EXAMPLE).expect("example file");
        let e = file.select(None).unwrap_err();
        assert!(
            e.starts_with("baseline file baselines-example.json has 3 entries; name the one to judge against with --purpose <entry id>:"),
            "{e}"
        );
        for entry in &file.entries {
            assert!(e.contains(&format!("\n  {}", entry.id)), "{e}");
            if let Some(case) = &entry.applies_when {
                assert!(e.contains(&format!("applies when: {case}")), "{e}");
            }
        }
        assert_eq!(
            file.select(Some("example.wine-shop.loyalty-card"))
                .expect("by id")
                .id,
            "example.wine-shop.loyalty-card"
        );
        assert!(file
            .select(Some("event_checkin"))
            .unwrap_err()
            .contains("built-in purpose"));
    }

    #[test]
    fn file_name_is_the_basename_only() {
        assert_eq!(
            file_name(Path::new("/some/dir/sub/my-baselines.json")),
            "my-baselines.json"
        );
        assert_eq!(
            file_name(Path::new("my-baselines.json")),
            "my-baselines.json"
        );
        assert_eq!(file_name(Path::new("../x/b.json")), "b.json");

        let dir = std::env::temp_dir().join(format!("augenmass-baseline-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("nested")).expect("dir");
        let path = dir.join("nested").join("broken.json");
        std::fs::write(&path, "{ \"schema\": \"other/1.0\" }").expect("write");
        let e = load(&path).expect_err("broken").to_string();
        assert_eq!(
            e,
            "baseline file broken.json: schema: unknown schema id \"other/1.0\"; this version reads only \"augenmass-baselines/0.1\""
        );
        let e = load(&dir.join("nested").join("missing.json"))
            .expect_err("missing")
            .to_string();
        assert!(
            e.starts_with("baseline file missing.json: cannot be read: "),
            "{e}"
        );
        assert!(!e.contains("nested"), "{e}");
    }
}
