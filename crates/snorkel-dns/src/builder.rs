use snorkel_common::types::{Question, QueryType};

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

/// Write a 12-byte header-only DNS response with the given query ID and RCODE.
/// Used for error responses on parse failure where we don't have a fully
/// parsed Question to echo. Clients tolerate empty response bodies on error.
pub fn build_error_header(
    out: &mut [u8],
    query_id: u16,
    rcode: u8,
) -> Result<usize, BuildError> {
    let flags: u16 = 0x8000 | (u16::from(rcode) & 0x000f);
    let mut cursor: usize = 0;
    cursor = write_u16(out, cursor, query_id)?;
    cursor = write_u16(out, cursor, flags)?;
    cursor = write_u16(out, cursor, 0)?;
    cursor = write_u16(out, cursor, 0)?;
    cursor = write_u16(out, cursor, 0)?;
    cursor = write_u16(out, cursor, 0)?;
    Ok(cursor)
}

#[derive(Debug, Clone, Copy)]
pub enum ResponseKind<'a> {
    A { addr: [u8; 4] },
    Aaaa { addr: [u8; 16] },
    Cname { target: &'a [u8] },
    Txt { content_uri: &'a [u8] },
    NxDomain,
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    BufferTooSmall,
    QnameMalformed,
    ContentUriTooLong,
}

const TTL_SECONDS: u32 = 300;
const CLASS_IN: u16 = 0x0001;
const MAX_TXT_STRING: usize = 255;
const MAX_DNS_LABEL: usize = 63;

pub fn build_response(
    out: &mut [u8],
    query_id: u16,
    question: &Question,
    kind: ResponseKind<'_>,
) -> Result<usize, BuildError> {
    let (flags, ancount) = match kind {
        ResponseKind::A { .. }
        | ResponseKind::Aaaa { .. }
        | ResponseKind::Cname { .. }
        | ResponseKind::Txt { .. } => (0x8180_u16, 1_u16),
        ResponseKind::NxDomain => (0x8183_u16, 0_u16),
        ResponseKind::Refused => (0x8185_u16, 0_u16),
    };

    let mut cursor: usize = 0;
    cursor = write_u16(out, cursor, query_id)?;
    cursor = write_u16(out, cursor, flags)?;
    cursor = write_u16(out, cursor, 1)?;
    cursor = write_u16(out, cursor, ancount)?;
    cursor = write_u16(out, cursor, 0)?;
    cursor = write_u16(out, cursor, 0)?;

    cursor = write_qname(out, cursor, &question.qname)?;
    cursor = write_u16(out, cursor, question.qtype.to_wire())?;
    cursor = write_u16(out, cursor, CLASS_IN)?;

    match kind {
        ResponseKind::NxDomain | ResponseKind::Refused => {}
        ResponseKind::A { addr } => {
            cursor = write_answer_header(out, cursor, &question.qname, QueryType::A)?;
            cursor = write_u16(out, cursor, 4)?;
            cursor = write_bytes(out, cursor, &addr)?;
        }
        ResponseKind::Aaaa { addr } => {
            cursor = write_answer_header(out, cursor, &question.qname, QueryType::Aaaa)?;
            cursor = write_u16(out, cursor, 16)?;
            cursor = write_bytes(out, cursor, &addr)?;
        }
        ResponseKind::Cname { target } => {
            cursor = write_answer_header(out, cursor, &question.qname, QueryType::Cname)?;
            let rdlength_pos = cursor;
            cursor = cursor.checked_add(2).ok_or(BuildError::BufferTooSmall)?;
            let rdata_start = cursor;
            cursor = write_qname(out, cursor, target)?;
            let rdata_end = cursor;
            let rdlength = rdata_end
                .checked_sub(rdata_start)
                .ok_or(BuildError::BufferTooSmall)?;
            let rdlength_u16: u16 = rdlength
                .try_into()
                .map_err(|_| BuildError::BufferTooSmall)?;
            write_u16(out, rdlength_pos, rdlength_u16)?;
        }
        ResponseKind::Txt { content_uri } => {
            if content_uri.len() > MAX_TXT_STRING {
                return Err(BuildError::ContentUriTooLong);
            }
            cursor = write_answer_header(out, cursor, &question.qname, QueryType::Txt)?;
            let rdlength = content_uri
                .len()
                .checked_add(1)
                .ok_or(BuildError::ContentUriTooLong)?;
            let rdlength_u16: u16 = rdlength
                .try_into()
                .map_err(|_| BuildError::ContentUriTooLong)?;
            cursor = write_u16(out, cursor, rdlength_u16)?;
            let len_u8: u8 = content_uri
                .len()
                .try_into()
                .map_err(|_| BuildError::ContentUriTooLong)?;
            cursor = write_u8(out, cursor, len_u8)?;
            cursor = write_bytes(out, cursor, content_uri)?;
        }
    }

    Ok(cursor)
}

fn write_answer_header(
    out: &mut [u8],
    at: usize,
    qname: &[u8],
    rtype: QueryType,
) -> Result<usize, BuildError> {
    let mut cursor = write_qname(out, at, qname)?;
    cursor = write_u16(out, cursor, rtype.to_wire())?;
    cursor = write_u16(out, cursor, CLASS_IN)?;
    cursor = write_u32(out, cursor, TTL_SECONDS)?;
    Ok(cursor)
}

fn write_u8(out: &mut [u8], at: usize, val: u8) -> Result<usize, BuildError> {
    let slot = out.get_mut(at).ok_or(BuildError::BufferTooSmall)?;
    *slot = val;
    at.checked_add(1).ok_or(BuildError::BufferTooSmall)
}

fn write_u16(out: &mut [u8], at: usize, val: u16) -> Result<usize, BuildError> {
    let end = at.checked_add(2).ok_or(BuildError::BufferTooSmall)?;
    let slice = out.get_mut(at..end).ok_or(BuildError::BufferTooSmall)?;
    slice.copy_from_slice(&val.to_be_bytes());
    Ok(end)
}

fn write_u32(out: &mut [u8], at: usize, val: u32) -> Result<usize, BuildError> {
    let end = at.checked_add(4).ok_or(BuildError::BufferTooSmall)?;
    let slice = out.get_mut(at..end).ok_or(BuildError::BufferTooSmall)?;
    slice.copy_from_slice(&val.to_be_bytes());
    Ok(end)
}

fn write_bytes(out: &mut [u8], at: usize, bytes: &[u8]) -> Result<usize, BuildError> {
    let end = at.checked_add(bytes.len()).ok_or(BuildError::BufferTooSmall)?;
    let slice = out.get_mut(at..end).ok_or(BuildError::BufferTooSmall)?;
    slice.copy_from_slice(bytes);
    Ok(end)
}

fn write_qname(out: &mut [u8], at: usize, qname: &[u8]) -> Result<usize, BuildError> {
    let mut cursor = at;
    for label in qname.split(|&b| b == b'.') {
        if label.is_empty() || label.len() > MAX_DNS_LABEL {
            return Err(BuildError::QnameMalformed);
        }
        let len_u8: u8 = label
            .len()
            .try_into()
            .map_err(|_| BuildError::QnameMalformed)?;
        cursor = write_u8(out, cursor, len_u8)?;
        cursor = write_bytes(out, cursor, label)?;
    }
    write_u8(out, cursor, 0)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn sample_question(qtype: QueryType) -> Question {
        Question {
            qname: b"alice.dot".to_vec(),
            qtype,
        }
    }

    #[test]
    fn build_nxdomain_sets_rcode_three() {
        let mut buf = [0_u8; 512];
        let n = build_response(
            &mut buf,
            0xabcd,
            &sample_question(QueryType::Txt),
            ResponseKind::NxDomain,
        )
        .unwrap();
        assert!(n >= 12);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        assert_eq!(flags & 0x000f, 3);
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        assert_eq!(ancount, 0);
    }

    #[test]
    fn build_refused_sets_rcode_five() {
        let mut buf = [0_u8; 512];
        let _ = build_response(
            &mut buf,
            0xabcd,
            &sample_question(QueryType::Txt),
            ResponseKind::Refused,
        )
        .unwrap();
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        assert_eq!(flags & 0x000f, 5);
    }

    #[test]
    fn build_a_includes_answer() {
        let mut buf = [0_u8; 512];
        let n = build_response(
            &mut buf,
            0xabcd,
            &sample_question(QueryType::A),
            ResponseKind::A {
                addr: [192, 0, 2, 1],
            },
        )
        .unwrap();
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        assert_eq!(ancount, 1);
        assert!(n > 12);
    }

    #[test]
    fn build_aaaa_includes_answer() {
        let mut buf = [0_u8; 512];
        let n = build_response(
            &mut buf,
            0xabcd,
            &sample_question(QueryType::Aaaa),
            ResponseKind::Aaaa {
                addr: [
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ],
            },
        )
        .unwrap();
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        assert_eq!(ancount, 1);
        assert!(n > 12);
    }

    #[test]
    fn build_cname_includes_answer() {
        let mut buf = [0_u8; 512];
        let target = b"gateway.dot.substrate.icu";
        let n = build_response(
            &mut buf,
            0xabcd,
            &sample_question(QueryType::Cname),
            ResponseKind::Cname { target },
        )
        .unwrap();
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        assert_eq!(ancount, 1);
        assert!(n > 12);
    }

    #[test]
    fn build_txt_includes_answer() {
        let mut buf = [0_u8; 512];
        let uri = b"ipfs://bafybeifoo";
        let n = build_response(
            &mut buf,
            0xabcd,
            &sample_question(QueryType::Txt),
            ResponseKind::Txt { content_uri: uri },
        )
        .unwrap();
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        assert_eq!(ancount, 1);
        assert!(n > 12);
    }

    #[test]
    fn content_uri_too_long_rejected() {
        let mut buf = [0_u8; 1024];
        let long = vec![b'x'; 256];
        let err = build_response(
            &mut buf,
            0xabcd,
            &sample_question(QueryType::Txt),
            ResponseKind::Txt { content_uri: &long },
        );
        assert!(matches!(err, Err(BuildError::ContentUriTooLong)));
    }

    #[test]
    fn tiny_buffer_rejected() {
        let mut buf = [0_u8; 4];
        let err = build_response(
            &mut buf,
            0xabcd,
            &sample_question(QueryType::Txt),
            ResponseKind::NxDomain,
        );
        assert!(matches!(err, Err(BuildError::BufferTooSmall)));
    }
}
