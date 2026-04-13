use snorkel_common::types::{NameRecord, QueryType};

use crate::builder::{build_response, BuildError, ResponseKind};
use crate::parser::{parse_query, ParseError};

#[derive(Debug)]
pub enum DispatchError {
    Parse(ParseError),
    Build(BuildError),
    LocalLabelMissing,
}

pub trait CacheLookup {
    fn lookup(&self, label: &[u8]) -> Option<NameRecord>;
}

pub struct Dispatcher<'a, L: CacheLookup> {
    pub zone: &'a [u8],
    pub gateway_v4: Option<[u8; 4]>,
    pub gateway_v6: Option<[u8; 16]>,
    pub cache: &'a L,
}

impl<'a, L: CacheLookup> Dispatcher<'a, L> {
    pub fn handle(&self, query_buf: &[u8], out: &mut [u8]) -> Result<usize, DispatchError> {
        let parsed = parse_query(query_buf, self.zone).map_err(DispatchError::Parse)?;

        let local_label = strip_zone_suffix(&parsed.question.qname, self.zone)
            .ok_or(DispatchError::LocalLabelMissing)?;

        let record = self.cache.lookup(local_label);
        let kind = self.resolve(parsed.question.qtype, record.as_ref());

        build_response(out, parsed.id, &parsed.question, kind).map_err(DispatchError::Build)
    }

    pub fn resolve<'r>(&self, qtype: QueryType, record: Option<&'r NameRecord>) -> ResponseKind<'r> {
        let Some(record) = record else {
            return ResponseKind::NxDomain;
        };

        match qtype {
            QueryType::A => {
                if let Some(addr) = record.a {
                    return ResponseKind::A { addr };
                }
                if record.content.is_some() {
                    if let Some(addr) = self.gateway_v4 {
                        return ResponseKind::A { addr };
                    }
                }
                ResponseKind::NxDomain
            }
            QueryType::Aaaa => {
                if let Some(addr) = record.aaaa {
                    return ResponseKind::Aaaa { addr };
                }
                if record.content.is_some() {
                    if let Some(addr) = self.gateway_v6 {
                        return ResponseKind::Aaaa { addr };
                    }
                }
                ResponseKind::NxDomain
            }
            QueryType::Cname => {
                if let Some(target) = &record.cname {
                    return ResponseKind::Cname { target };
                }
                ResponseKind::NxDomain
            }
            QueryType::Txt => {
                if let Some(content_uri) = &record.txt {
                    return ResponseKind::Txt { content_uri };
                }
                ResponseKind::NxDomain
            }
            _ => ResponseKind::NxDomain,
        }
    }
}

pub fn strip_zone_suffix<'a>(qname: &'a [u8], zone: &[u8]) -> Option<&'a [u8]> {
    if qname == zone {
        return Some(&[]);
    }
    if qname.len() <= zone.len() {
        return None;
    }
    let separator_pos = qname.len().checked_sub(zone.len())?.checked_sub(1)?;
    let local = qname.get(..separator_pos)?;
    let dot = qname.get(separator_pos)?;
    if *dot != b'.' {
        return None;
    }
    let suffix_start = separator_pos.checked_add(1)?;
    let suffix = qname.get(suffix_start..)?;
    if suffix != zone {
        return None;
    }
    Some(local)
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
    use std::collections::HashMap;

    struct StubCache {
        records: HashMap<Vec<u8>, NameRecord>,
    }

    impl CacheLookup for StubCache {
        fn lookup(&self, label: &[u8]) -> Option<NameRecord> {
            self.records.get(label).cloned()
        }
    }

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
    fn strips_single_label_zone() {
        let result = strip_zone_suffix(b"bob.dot", b"dot");
        assert_eq!(result, Some(b"bob".as_slice()));
    }

    #[test]
    fn strips_multi_label_zone() {
        let result = strip_zone_suffix(b"bob.dot.substrate.icu", b"dot.substrate.icu");
        assert_eq!(result, Some(b"bob".as_slice()));
    }

    #[test]
    fn strips_multi_label_local() {
        let result = strip_zone_suffix(b"alice.bob.dot.substrate.icu", b"dot.substrate.icu");
        assert_eq!(result, Some(b"alice.bob".as_slice()));
    }

    #[test]
    fn returns_empty_for_zone_apex() {
        let result = strip_zone_suffix(b"dot.substrate.icu", b"dot.substrate.icu");
        assert_eq!(result, Some(b"".as_slice()));
    }

    #[test]
    fn rejects_wrong_zone() {
        let result = strip_zone_suffix(b"bob.com", b"dot");
        assert_eq!(result, None);
    }

    #[test]
    fn nxdomain_when_cache_miss() {
        let cache = StubCache {
            records: HashMap::new(),
        };
        let dispatcher = Dispatcher {
            zone: b"dot",
            gateway_v4: None,
            gateway_v6: None,
            cache: &cache,
        };
        let buf = make_query(&[b"alice", b"dot"], 0x0001);
        let mut out = [0_u8; 512];
        let n = dispatcher.handle(&buf, &mut out).unwrap();
        let flags = u16::from_be_bytes([out[2], out[3]]);
        assert_eq!(flags & 0x000f, 3);
        assert!(n >= 12);
    }

    #[test]
    fn returns_a_record_from_cache() {
        let mut records = HashMap::new();
        records.insert(
            b"alice".to_vec(),
            NameRecord {
                a: Some([192, 0, 2, 7]),
                ..NameRecord::default()
            },
        );
        let cache = StubCache { records };
        let dispatcher = Dispatcher {
            zone: b"dot",
            gateway_v4: None,
            gateway_v6: None,
            cache: &cache,
        };
        let buf = make_query(&[b"alice", b"dot"], 0x0001);
        let mut out = [0_u8; 512];
        let _ = dispatcher.handle(&buf, &mut out).unwrap();
        let ancount = u16::from_be_bytes([out[6], out[7]]);
        assert_eq!(ancount, 1);
    }

    #[test]
    fn content_falls_back_to_gateway_a() {
        let mut records = HashMap::new();
        records.insert(
            b"alice".to_vec(),
            NameRecord {
                content: Some(b"ipfs://bafybeifoo".to_vec()),
                ..NameRecord::default()
            },
        );
        let cache = StubCache { records };
        let dispatcher = Dispatcher {
            zone: b"dot",
            gateway_v4: Some([198, 51, 100, 1]),
            gateway_v6: None,
            cache: &cache,
        };
        let buf = make_query(&[b"alice", b"dot"], 0x0001);
        let mut out = [0_u8; 512];
        let _ = dispatcher.handle(&buf, &mut out).unwrap();
        let ancount = u16::from_be_bytes([out[6], out[7]]);
        assert_eq!(ancount, 1);
    }

    #[test]
    fn content_without_gateway_returns_nxdomain() {
        let mut records = HashMap::new();
        records.insert(
            b"alice".to_vec(),
            NameRecord {
                content: Some(b"ipfs://bafybeifoo".to_vec()),
                ..NameRecord::default()
            },
        );
        let cache = StubCache { records };
        let dispatcher = Dispatcher {
            zone: b"dot",
            gateway_v4: None,
            gateway_v6: None,
            cache: &cache,
        };
        let buf = make_query(&[b"alice", b"dot"], 0x0001);
        let mut out = [0_u8; 512];
        let _ = dispatcher.handle(&buf, &mut out).unwrap();
        let flags = u16::from_be_bytes([out[2], out[3]]);
        assert_eq!(flags & 0x000f, 3);
    }
}
