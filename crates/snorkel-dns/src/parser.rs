use snorkel_common::types::{Question, QueryType};

pub fn extract_query_id(buf: &[u8]) -> Option<u16> {
    let hi = *buf.first()?;
    let lo = *buf.get(1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedQuery {
    pub id: u16,
    pub question: Question,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    NotQuery,
    UnsupportedOpcode,
    WrongSectionCounts,
    ClassNotInternet,
    CompressionNotSupported,
    LabelTooLong,
    QnameTooLong,
    QnameMalformed,
    QnameNotInZone,
    UnsupportedQtype,
}

const DNS_HEADER_SIZE: usize = 12;
const MAX_QNAME_BYTES: usize = 255;
const MAX_LABEL_BYTES: u8 = 63;
const CLASS_IN: u16 = 0x0001;

pub fn parse_query(buf: &[u8], zone: &[u8]) -> Result<ParsedQuery, ParseError> {
    let id = read_u16(buf, 0)?;
    let flags = read_u16(buf, 2)?;
    let qdcount = read_u16(buf, 4)?;
    let ancount = read_u16(buf, 6)?;
    let nscount = read_u16(buf, 8)?;
    let arcount = read_u16(buf, 10)?;

    if (flags & 0x8000) != 0 {
        return Err(ParseError::NotQuery);
    }
    if ((flags >> 11) & 0x0f) != 0 {
        return Err(ParseError::UnsupportedOpcode);
    }
    // Allow arcount > 0 to tolerate EDNS0 OPT records in the additional section.
    // We don't parse OPT contents but accept their presence (dig sends them by default).
    let _ = arcount;
    if qdcount != 1 || ancount != 0 || nscount != 0 {
        return Err(ParseError::WrongSectionCounts);
    }

    let (qname, after_qname) = parse_qname(buf, DNS_HEADER_SIZE)?;
    let raw_qtype = read_u16(buf, after_qname)?;
    let qclass_offset = after_qname.checked_add(2).ok_or(ParseError::TooShort)?;
    let qclass = read_u16(buf, qclass_offset)?;
    let _end_offset = qclass_offset.checked_add(2).ok_or(ParseError::TooShort)?;

    if qclass != CLASS_IN {
        return Err(ParseError::ClassNotInternet);
    }
    // Trailing bytes after the question section are silently ignored
    // (they may be EDNS0 OPT records or other additional-section content).
    if !qname_is_in_zone(&qname, zone) {
        return Err(ParseError::QnameNotInZone);
    }

    let qtype = QueryType::from_wire(raw_qtype).ok_or(ParseError::UnsupportedQtype)?;

    Ok(ParsedQuery {
        id,
        question: Question { qname, qtype },
    })
}

fn read_u16(buf: &[u8], start: usize) -> Result<u16, ParseError> {
    let end = start.checked_add(2).ok_or(ParseError::TooShort)?;
    let slice = buf.get(start..end).ok_or(ParseError::TooShort)?;
    let arr: [u8; 2] = slice.try_into().map_err(|_| ParseError::TooShort)?;
    Ok(u16::from_be_bytes(arr))
}

fn parse_qname(buf: &[u8], start: usize) -> Result<(Vec<u8>, usize), ParseError> {
    let mut qname: Vec<u8> = Vec::with_capacity(64);
    let mut offset = start;
    let mut total_len: usize = 0;

    loop {
        let len_byte = *buf.get(offset).ok_or(ParseError::TooShort)?;
        offset = offset.checked_add(1).ok_or(ParseError::TooShort)?;

        if len_byte == 0 {
            return Ok((qname, offset));
        }
        if (len_byte & 0xc0) != 0 {
            return Err(ParseError::CompressionNotSupported);
        }
        if len_byte > MAX_LABEL_BYTES {
            return Err(ParseError::LabelTooLong);
        }

        let label_len = usize::from(len_byte);
        let label_end = offset.checked_add(label_len).ok_or(ParseError::TooShort)?;
        let label = buf.get(offset..label_end).ok_or(ParseError::TooShort)?;

        let increment = label_len.checked_add(1).ok_or(ParseError::QnameTooLong)?;
        total_len = total_len.checked_add(increment).ok_or(ParseError::QnameTooLong)?;
        if total_len > MAX_QNAME_BYTES {
            return Err(ParseError::QnameTooLong);
        }

        if !qname.is_empty() {
            qname.push(b'.');
        }
        for &b in label {
            if b.is_ascii_uppercase() {
                qname.push(b.to_ascii_lowercase());
            } else if b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' {
                qname.push(b);
            } else {
                return Err(ParseError::QnameMalformed);
            }
        }

        offset = label_end;
    }
}

fn qname_is_in_zone(qname: &[u8], zone: &[u8]) -> bool {
    if qname == zone {
        return true;
    }
    let Some(dot_zone_len) = zone.len().checked_add(1) else {
        return false;
    };
    if qname.len() <= zone.len() {
        return false;
    }
    let Some(tail_start) = qname.len().checked_sub(dot_zone_len) else {
        return false;
    };
    let Some(tail) = qname.get(tail_start..) else {
        return false;
    };
    matches!(tail.first(), Some(&b'.')) && tail.get(1..) == Some(zone)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn make_query(labels: &[&[u8]], qtype: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x1234_u16.to_be_bytes());
        buf.extend_from_slice(&0x0100_u16.to_be_bytes());
        buf.extend_from_slice(&1_u16.to_be_bytes());
        buf.extend_from_slice(&0_u16.to_be_bytes());
        buf.extend_from_slice(&0_u16.to_be_bytes());
        buf.extend_from_slice(&0_u16.to_be_bytes());
        for label in labels {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label);
        }
        buf.push(0);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&1_u16.to_be_bytes());
        buf
    }

    #[test]
    fn empty_buffer_is_too_short() {
        assert!(matches!(parse_query(&[], b"dot"), Err(ParseError::TooShort)));
    }

    #[test]
    fn valid_txt_query_parses() {
        let buf = make_query(&[b"alice", b"dot"], 0x0010);
        let parsed = parse_query(&buf, b"dot").unwrap();
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.question.qname, b"alice.dot");
        assert_eq!(parsed.question.qtype, QueryType::Txt);
    }

    #[test]
    fn wrong_zone_rejected() {
        let buf = make_query(&[b"alice", b"com"], 0x0010);
        assert!(matches!(
            parse_query(&buf, b"dot"),
            Err(ParseError::QnameNotInZone)
        ));
    }

    #[test]
    fn unsupported_qtype_rejected() {
        let buf = make_query(&[b"alice", b"dot"], 0x000f);
        assert!(matches!(
            parse_query(&buf, b"dot"),
            Err(ParseError::UnsupportedQtype)
        ));
    }

    #[test]
    fn uppercase_is_lowercased() {
        let buf = make_query(&[b"Alice", b"DOT"], 0x0010);
        let parsed = parse_query(&buf, b"dot").unwrap();
        assert_eq!(parsed.question.qname, b"alice.dot");
    }

    #[test]
    fn trailing_bytes_tolerated() {
        let mut buf = make_query(&[b"alice", b"dot"], 0x0010);
        buf.push(0xff);
        let parsed = parse_query(&buf, b"dot").unwrap();
        assert_eq!(parsed.question.qname, b"alice.dot");
    }

    #[test]
    fn compression_pointer_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x1234_u16.to_be_bytes());
        buf.extend_from_slice(&0x0100_u16.to_be_bytes());
        buf.extend_from_slice(&1_u16.to_be_bytes());
        buf.extend_from_slice(&0_u16.to_be_bytes());
        buf.extend_from_slice(&0_u16.to_be_bytes());
        buf.extend_from_slice(&0_u16.to_be_bytes());
        buf.push(0xc0);
        buf.push(0x0c);
        buf.extend_from_slice(&0x0010_u16.to_be_bytes());
        buf.extend_from_slice(&1_u16.to_be_bytes());
        assert!(matches!(
            parse_query(&buf, b"dot"),
            Err(ParseError::CompressionNotSupported)
        ));
    }
}
