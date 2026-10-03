use std::ops::Range;

use super::{DnsName, EdnsMetadata, HEADER_LEN, OPT_TYPE, QueryError};

const MAX_POINTER_HOPS: usize = 128;

pub(crate) struct NameParseState {
    visited: Vec<u32>,
    epoch: u32,
    pointer_hops: usize,
}

impl NameParseState {
    pub(crate) fn new(message_len: usize) -> Self {
        Self {
            visited: vec![0; message_len],
            epoch: 0,
            pointer_hops: 0,
        }
    }

    fn begin_name(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        if self.epoch == 0 {
            self.visited.fill(0);
            self.epoch = 1;
        }
        self.pointer_hops = 0;
    }

    fn visit_pointer(&mut self, target: usize, cursor: usize) -> Result<(), QueryError> {
        if target >= cursor {
            return Err(QueryError::MalformedName);
        }
        self.pointer_hops += 1;
        if self.pointer_hops > MAX_POINTER_HOPS {
            return Err(QueryError::MalformedName);
        }
        let mark = self
            .visited
            .get_mut(target)
            .ok_or(QueryError::MalformedName)?;
        if *mark == self.epoch {
            return Err(QueryError::MalformedName);
        }
        *mark = self.epoch;
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct ResourceRecord {
    pub(super) name: DnsName,
    pub(super) rtype: u16,
    pub(super) class: u16,
    pub(super) ttl: u32,
    pub(super) rdata: Range<usize>,
    pub(super) end: usize,
}

struct RrFields {
    rtype: u16,
    class: u16,
    ttl: u32,
    rdata: Range<usize>,
    end: usize,
}

pub(super) fn parse_rr(
    raw: &[u8],
    start: usize,
    state: &mut NameParseState,
) -> Result<ResourceRecord, QueryError> {
    let mut wire = [0; 255];
    let (length, fields) = parse_rr_into(raw, start, state, &mut wire)?;
    Ok(ResourceRecord {
        name: DnsName(wire[..length].into()),
        rtype: fields.rtype,
        class: fields.class,
        ttl: fields.ttl,
        rdata: fields.rdata,
        end: fields.end,
    })
}

fn parse_rr_into(
    raw: &[u8],
    start: usize,
    state: &mut NameParseState,
    wire: &mut [u8; 255],
) -> Result<(usize, RrFields), QueryError> {
    let (length, name_end) = parse_name_into(raw, start, state, wire)?;
    let rtype = read_u16(raw, name_end)?;
    let class = read_u16(raw, name_end + 2)?;
    let ttl = read_u32(raw, name_end + 4)?;
    let rdlength = usize::from(read_u16(raw, name_end + 8)?);
    let rdata_start = name_end + 10;
    let end = rdata_start
        .checked_add(rdlength)
        .filter(|end| *end <= raw.len())
        .ok_or(QueryError::TruncatedField)?;
    Ok((
        length,
        RrFields {
            rtype,
            class,
            ttl,
            rdata: rdata_start..end,
            end,
        },
    ))
}

fn walk_edns_options(
    raw: &[u8],
    rdata: &Range<usize>,
    mut each: impl FnMut(u16),
) -> Result<(), QueryError> {
    let mut cursor = rdata.start;
    while cursor < rdata.end {
        let code = read_u16(raw, cursor).map_err(|_| QueryError::MalformedEdnsOption)?;
        let len =
            usize::from(read_u16(raw, cursor + 2).map_err(|_| QueryError::MalformedEdnsOption)?);
        cursor = cursor
            .checked_add(4 + len)
            .filter(|end| *end <= rdata.end)
            .ok_or(QueryError::MalformedEdnsOption)?;
        each(code);
    }
    Ok(())
}

fn require_root_owner(name: &[u8]) -> Result<(), QueryError> {
    if name != [0] {
        return Err(QueryError::MalformedName);
    }
    Ok(())
}

pub(super) fn parse_edns(raw: &[u8], rr: &ResourceRecord) -> Result<EdnsMetadata, QueryError> {
    let mut option_codes = Vec::new();
    walk_edns_options(raw, &rr.rdata, |code| option_codes.push(code))?;
    require_root_owner(rr.name.0.as_ref())?;
    let flags = u16::try_from(rr.ttl & 0xffff).map_err(|_| QueryError::TruncatedField)?;
    Ok(EdnsMetadata {
        advertised_size: rr.class,
        extended_rcode: u8::try_from(rr.ttl >> 24).map_err(|_| QueryError::TruncatedField)?,
        version: u8::try_from((rr.ttl >> 16) & 0xff).map_err(|_| QueryError::TruncatedField)?,
        dnssec_ok: flags & 0x8000 != 0,
        option_codes,
        flags,
    })
}

/// Allocation-free twin of the walk in `QueryContext::parse_with_profile` for a
/// one-question query: accepts exactly what it accepts and, because UDP ingress
/// needs only that, returns the first OPT's advertised size. The question name
/// must also decode as UTF-8 labels, as `DnsName::to_domain_name` requires.
pub(super) fn scan_single_question_query(raw: &[u8]) -> Result<Option<u16>, QueryError> {
    if raw.len() < HEADER_LEN {
        return Err(QueryError::HeaderTruncated);
    }
    let counts = [read_u16(raw, 6)?, read_u16(raw, 8)?, read_u16(raw, 10)?];
    let mut state = NameParseState::new(raw.len());
    let mut wire = [0; 255];
    let (length, mut cursor) = parse_name_into(raw, HEADER_LEN, &mut state, &mut wire)?;
    if !is_utf8_wire_name(&wire[..length]) {
        return Err(QueryError::MalformedName);
    }
    read_u16(raw, cursor)?;
    read_u16(raw, cursor + 2)?;
    cursor += 4;
    let mut advertised_size = None;
    for (section, count) in counts.into_iter().enumerate() {
        for _ in 0..count {
            let (length, rr) = parse_rr_into(raw, cursor, &mut state, &mut wire)?;
            cursor = rr.end;
            if section == 2 && rr.rtype == OPT_TYPE {
                walk_edns_options(raw, &rr.rdata, |_| {})?;
                require_root_owner(&wire[..length])?;
                advertised_size.get_or_insert(rr.class);
            }
        }
    }
    if cursor != raw.len() {
        return Err(QueryError::TrailingBytes);
    }
    Ok(advertised_size)
}

fn is_utf8_wire_name(wire: &[u8]) -> bool {
    let mut cursor = 0usize;
    loop {
        let Some(&length) = wire.get(cursor) else {
            return false;
        };
        cursor += 1;
        if length == 0 {
            return cursor == wire.len();
        }
        let Some(label) = wire.get(cursor..cursor + usize::from(length)) else {
            return false;
        };
        if std::str::from_utf8(label).is_err() {
            return false;
        }
        cursor += usize::from(length);
    }
}

pub(crate) fn parse_name(
    raw: &[u8],
    start: usize,
    state: &mut NameParseState,
) -> Result<(DnsName, usize), QueryError> {
    let mut wire = [0; 255];
    let (length, end) = parse_name_into(raw, start, state, &mut wire)?;
    Ok((DnsName(wire[..length].into()), end))
}

pub(crate) fn parse_name_into(
    raw: &[u8],
    start: usize,
    state: &mut NameParseState,
    wire: &mut [u8; 255],
) -> Result<(usize, usize), QueryError> {
    state.begin_name();
    let mut cursor = start;
    let mut end = None;
    let mut length = 0;
    loop {
        let octet = *raw.get(cursor).ok_or(QueryError::MalformedName)?;
        if octet & 0xc0 == 0xc0 {
            let second = *raw.get(cursor + 1).ok_or(QueryError::MalformedName)?;
            let target = usize::from((u16::from(octet & 0x3f) << 8) | u16::from(second));
            state.visit_pointer(target, cursor)?;
            if end.is_none() {
                end = Some(cursor + 2);
            }
            cursor = target;
            continue;
        }
        if octet & 0xc0 != 0 || octet > 63 {
            return Err(QueryError::MalformedName);
        }
        *wire.get_mut(length).ok_or(QueryError::MalformedName)? = octet;
        length += 1;
        cursor += 1;
        if octet == 0 {
            return Ok((length, end.unwrap_or(cursor)));
        }
        let label_end = cursor + usize::from(octet);
        let output_end = length + usize::from(octet);
        wire.get_mut(length..output_end)
            .ok_or(QueryError::MalformedName)?
            .copy_from_slice(
                raw.get(cursor..label_end)
                    .ok_or(QueryError::MalformedName)?,
            );
        length = output_end;
        cursor = label_end;
    }
}

pub(super) fn read_u16(raw: &[u8], offset: usize) -> Result<u16, QueryError> {
    let bytes = raw
        .get(offset..offset + 2)
        .ok_or(QueryError::TruncatedField)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(raw: &[u8], offset: usize) -> Result<u32, QueryError> {
    let bytes = raw
        .get(offset..offset + 4)
        .ok_or(QueryError::TruncatedField)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}
