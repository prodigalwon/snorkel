pub type Hash32 = [u8; 32];
pub type NameHash = Hash32;
pub type BlockHash = Hash32;
pub type BlockNumber = u32;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NameRecord {
    pub a: Option<[u8; 4]>,
    pub aaaa: Option<[u8; 16]>,
    pub cname: Option<Vec<u8>>,
    pub txt: Option<Vec<u8>>,
    pub content: Option<Vec<u8>>,
    pub expires_at: BlockNumber,
    pub verified_against: BlockHash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub qname: Vec<u8>,
    pub qtype: QueryType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum QueryType {
    A,
    Aaaa,
    Cname,
    Txt,
}

impl QueryType {
    pub const fn from_wire(qtype: u16) -> Option<Self> {
        match qtype {
            0x0001 => Some(Self::A),
            0x0005 => Some(Self::Cname),
            0x0010 => Some(Self::Txt),
            0x001c => Some(Self::Aaaa),
            _ => None,
        }
    }

    pub const fn to_wire(self) -> u16 {
        match self {
            Self::A => 0x0001,
            Self::Aaaa => 0x001c,
            Self::Cname => 0x0005,
            Self::Txt => 0x0010,
        }
    }
}
