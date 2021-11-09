pub mod parse;
pub mod types;

use carpenter::*;
use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    combinator::{map, verify},
    error::context,
    multi::many0,
    number::complete::{le_u16, le_u32},
    sequence::tuple,
    Offset,
};
use std::fmt::{self, Debug};

use types::*;

struct HexDump<'a>(&'a [u8]);
impl<'a> Debug for HexDump<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &x in self.0.iter().take(20) {
            write!(f, "{:02x}", x)?;
        }
        Ok(())
    }
}

#[derive(PrettyTable)]
#[header("")]
pub struct HeaderInfo {
    pub count: usize,
    #[fmt("{:?}B")]
    pub size: usize,
}

impl Debug for HeaderInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get_table())
    }
}

#[derive(PrettyTable)]
pub struct FileHeader {
    pub typ: Type,
    pub machine: Machine,
    pub entry_point: Addr,
    #[skip]
    pub program_headers: Vec<ProgramHeader>,
    pub program_header_info: HeaderInfo,
    pub section_header_info: HeaderInfo,
    // pub section_headers: Vec<ProgramHeader>,
}

#[derive(thiserror::Error, Debug)]
pub enum RelaReadError {
    #[error("Rela dynamic entry not found")]
    RelaNotFound,
    #[error("Rela size entry not found")]
    RelaSizeNotFound,
    #[error("Rela segment not found")]
    RelaSegmentNotFound,
    #[error("Parsing failed")]
    RelaParseError(nom::error::VerboseErrorKind),
}

impl FileHeader {
    const MAGIC: &'static [u8] = &[0x7f, b'E', b'L', b'F'];

    pub fn segment_at(&self, addr: Addr) -> Option<&ProgramHeader> {
        self.program_headers
            .iter()
            .filter(|ph| ph.typ == SegmentType::Load)
            .find(|ph| ph.mem_range().contains(&addr))
    }

    pub fn segment_type(&self, typ: SegmentType) -> Option<&ProgramHeader> {
        self.program_headers.iter().find(|ph| ph.typ == typ)
    }

    pub fn dynamic_entry(&self, tag: DynamicTag) -> Option<Addr> {
        match self.segment_type(SegmentType::Dynamic) {
            Some(ProgramHeader {
                contents: SegmentContent::Dynamic(entries),
                ..
            }) => entries.iter().find(|e| e.tag == tag).map(|e| e.addr),
            _ => None,
        }
    }

    pub fn read_rela_entries(&self) -> Result<Vec<RelaEntry>, RelaReadError> {
        let start = self
            .dynamic_entry(DynamicTag::Rela)
            .ok_or(RelaReadError::RelaNotFound)?;
        let size = self
            .dynamic_entry(DynamicTag::RelaSz)
            .ok_or(RelaReadError::RelaSizeNotFound)?;
        let segment = self
            .segment_at(start)
            .ok_or(RelaReadError::RelaSegmentNotFound)?;

        let segstart = start - segment.mem_range().start;
        let input = &segment.data[segstart.into()..][..size.into()];

        match many0(RelaEntry::parse)(input) {
            Ok((_, entries)) => Ok(entries),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                let (_, e) = &err.errors[0];
                Err(RelaReadError::RelaParseError(e.clone()))
            }
            _ => unreachable!(),
        }
    }

    pub fn parse(input: parse::Input) -> parse::Result<Self> {
        let full = input;
        let (input, _) = tuple((
            context("Magic", tag(Self::MAGIC)),
            context("Class", tag(&[0x2])),
            context("Endianess", tag(&[0x1])),
            context("Version", tag(&[0x1])),
            context("OS ABI", alt((tag(&[0x0]), tag(&[0x3])))),
            context("Padding", take(8usize)),
        ))(input)?;

        let u16_usize = map(le_u16, |x| x as usize);

        let (input, (typ, machine)) = tuple((Type::parse, Machine::parse))(input)?;

        let (input, _) = context("Version (bis)", verify(le_u32, |&x| x == 1))(input)?;
        let (input, entry_point) = Addr::parse(input)?;

        let (input, (pho, sho)) = tuple((Addr::parse, Addr::parse))(input)?;
        let (input, (flags, hsize)) = tuple((le_u32, le_u16))(input)?;
        let (input, (psize, pcount)) = tuple((&u16_usize, &u16_usize))(input)?;
        let (input, (ssize, scount, name_idx)) =
            tuple((&u16_usize, &u16_usize, &u16_usize))(input)?;

        let mut program_headers = Vec::new();
        for pheader in (&full[pho.into()..]).chunks(psize).take(pcount) {
            let (_, header) = ProgramHeader::parse(full, pheader)?;
            program_headers.push(header);
        }

        Ok((
            input,
            Self {
                typ,
                machine,
                entry_point,
                program_headers,
                program_header_info: HeaderInfo {
                    size: psize,
                    count: pcount,
                },
                section_header_info: HeaderInfo {
                    size: ssize,
                    count: scount,
                },
            },
        ))
    }

    pub fn parse_or_print_error(input: parse::Input) -> Option<Self> {
        match Self::parse(input) {
            Ok((_, file)) => Some(file),
            Err(nom::Err::Failure(e)) | Err(nom::Err::Error(e)) => {
                eprintln!("Failed parsing input!");
                for (inp, err) in e.errors {
                    eprintln!("{:?} at:", err);
                    eprintln!("[{:#x}] {:?}", input.offset(inp), HexDump(inp));
                }
                None
            }
            Err(_) => panic!("Unexpected error occured while parsing."),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn type_as_u16() {
        assert_eq!(super::Type::Core as u16, 0x4);
        assert_eq!(super::Machine::X86_64 as u16, 0x3e);
    }

    #[test]
    fn type_from_u16() {
        use super::{Machine, Type};
        use std::convert::TryFrom;
        assert_eq!(Type::try_from(0x3), Ok(Type::Dyn));
        assert_eq!(Machine::try_from(0x03), Ok(Machine::X86));
        assert_eq!(Type::try_from(0x40), Err(0x40));
    }

    #[test]
    fn bitflags() {
        use super::SegmentFlags;
        use enumflags2::BitFlags;

        let flag_int = 6;
        let flags = BitFlags::<SegmentFlags>::from_bits(flag_int).unwrap();
        assert_eq!(flags.bits(), flag_int);
        assert_eq!(SegmentFlags::Read | SegmentFlags::Write, flags);
    }
}
