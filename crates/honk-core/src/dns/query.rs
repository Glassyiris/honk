use thiserror::Error;

mod parser;

pub(crate) use parser::parse_name;
use parser::{parse_edns, parse_rr};

const HEADER_LEN: usize = 12;
const OPT_TYPE: u16 = 41;
const ALLOWED_QUERY_FLAGS: u16 = 0x0130;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxId(u16);

impl TxId {
    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QType(u16);

impl QType {
    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QClass(u16);

impl QClass {
    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsName(Vec<u8>);

impl DnsName {
    pub fn as_wire(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum IngressProfile {
    Udp {
        advertised_size: u16,
    },
    Tcp,
    Api,
    #[default]
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuestionOffsets {
    start: usize,
    end: usize,
}

impl QuestionOffsets {
    pub const fn start(self) -> usize {
        self.start
    }

    pub const fn end(self) -> usize {
        self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsMetadata {
    advertised_size: u16,
    extended_rcode: u8,
    version: u8,
    dnssec_ok: bool,
    option_codes: Vec<u16>,
    flags: u16,
}

impl EdnsMetadata {
    pub const fn advertised_size(&self) -> u16 {
        self.advertised_size
    }

    pub const fn version(&self) -> u8 {
        self.version
    }

    pub const fn extended_rcode(&self) -> u8 {
        self.extended_rcode
    }

    pub const fn dnssec_ok(&self) -> bool {
        self.dnssec_ok
    }

    pub fn option_codes(&self) -> &[u16] {
        &self.option_codes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Question {
    name: DnsName,
    qtype: QType,
    qclass: QClass,
    offsets: QuestionOffsets,
}

#[derive(Debug, Clone)]
pub struct QueryContext {
    txid: TxId,
    flags: u16,
    questions: Vec<Question>,
    edns: Option<EdnsMetadata>,
    ingress: IngressProfile,
    canonical_wire: Vec<u8>,
    cacheable: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum QueryError {
    #[error("DNS message is shorter than its header")]
    HeaderTruncated,
    #[error("DNS message contains a malformed name")]
    MalformedName,
    #[error("DNS message contains a truncated field")]
    TruncatedField,
    #[error("DNS message contains a malformed EDNS option")]
    MalformedEdnsOption,
    #[error("DNS message has trailing bytes")]
    TrailingBytes,
}

impl QueryContext {
    pub fn parse(raw: &[u8]) -> Result<Self, QueryError> {
        Self::parse_with_profile(raw, IngressProfile::default())
    }

    pub fn parse_with_profile(raw: &[u8], ingress: IngressProfile) -> Result<Self, QueryError> {
        if raw.len() < HEADER_LEN {
            return Err(QueryError::HeaderTruncated);
        }
        let txid = TxId(read_u16(raw, 0)?);
        let flags = read_u16(raw, 2)?;
        let qdcount = read_u16(raw, 4)?;
        let ancount = read_u16(raw, 6)?;
        let nscount = read_u16(raw, 8)?;
        let arcount = read_u16(raw, 10)?;
        let mut cursor = HEADER_LEN;
        let mut questions = Vec::with_capacity(usize::from(qdcount));
        for _ in 0..qdcount {
            let start = cursor;
            let (name, end) = parse_name(raw, cursor)?;
            cursor = end;
            let qtype = QType(read_u16(raw, cursor)?);
            let qclass = QClass(read_u16(raw, cursor + 2)?);
            cursor += 4;
            questions.push(Question {
                name,
                qtype,
                qclass,
                offsets: QuestionOffsets { start, end: cursor },
            });
        }
        for _ in 0..ancount {
            cursor = parse_rr(raw, cursor)?.end;
        }
        for _ in 0..nscount {
            cursor = parse_rr(raw, cursor)?.end;
        }
        let mut edns = None;
        let mut opt_count = 0u16;
        for _ in 0..arcount {
            let rr = parse_rr(raw, cursor)?;
            cursor = rr.end;
            if rr.rtype == OPT_TYPE {
                opt_count = opt_count.saturating_add(1);
                let metadata = parse_edns(raw, &rr)?;
                if edns.is_none() {
                    edns = Some(metadata);
                }
            }
        }
        if cursor != raw.len() {
            return Err(QueryError::TrailingBytes);
        }
        let mut canonical_wire = raw.to_vec();
        if let Some(id) = canonical_wire.get_mut(0..2) {
            id.copy_from_slice(&[0, 0]);
        }
        let cacheable = flags & !ALLOWED_QUERY_FLAGS == 0
            && qdcount == 1
            && ancount == 0
            && nscount == 0
            && arcount == opt_count
            && opt_count <= 1
            && edns.as_ref().is_none_or(|value| {
                value.version == 0
                    && value.option_codes.is_empty()
                    && value.extended_rcode == 0
                    && value.flags & !0x8000 == 0
            });
        Ok(Self {
            txid,
            flags,
            questions,
            edns,
            ingress,
            canonical_wire,
            cacheable,
        })
    }

    pub const fn txid(&self) -> TxId {
        self.txid
    }

    pub fn qname(&self) -> Option<&DnsName> {
        self.questions.first().map(|question| &question.name)
    }

    pub fn qtype(&self) -> Option<QType> {
        self.questions.first().map(|question| question.qtype)
    }

    pub fn qclass(&self) -> Option<QClass> {
        self.questions.first().map(|question| question.qclass)
    }

    pub fn question_offsets(&self) -> Option<QuestionOffsets> {
        self.questions.first().map(|question| question.offsets)
    }

    pub fn all_question_offsets(&self) -> impl ExactSizeIterator<Item = QuestionOffsets> + '_ {
        self.questions.iter().map(|question| question.offsets)
    }

    pub fn question_wire(&self) -> Option<&[u8]> {
        let offsets = self.question_offsets()?;
        self.canonical_wire.get(offsets.start..offsets.end)
    }

    pub const fn edns(&self) -> Option<&EdnsMetadata> {
        self.edns.as_ref()
    }

    pub const fn ingress(&self) -> IngressProfile {
        self.ingress
    }

    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    pub const fn is_cacheable(&self) -> bool {
        self.cacheable
    }

    pub const fn is_coalescable(&self) -> bool {
        self.cacheable
    }

    pub(crate) const fn flags(&self) -> u16 {
        self.flags
    }

    pub(crate) fn questions(&self) -> impl ExactSizeIterator<Item = (&DnsName, QType, QClass)> {
        self.questions
            .iter()
            .map(|question| (&question.name, question.qtype, question.qclass))
    }
}

fn read_u16(raw: &[u8], offset: usize) -> Result<u16, QueryError> {
    let bytes = raw
        .get(offset..offset + 2)
        .ok_or(QueryError::TruncatedField)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[cfg(test)]
mod tests;
