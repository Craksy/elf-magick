pub mod parse;
pub mod types;

use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    combinator::{map, verify},
    error::context,
    number::complete::{le_u16, le_u32},
    sequence::tuple,
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

#[derive(Debug)]
pub struct File {
    pub typ: Type,
    pub machine: Machine,
    pub entry_point: Addr,
    pub program_headers: Vec<ProgramHeader>,
    pub prog_header_info: (usize, usize),
    pub sect_header_info: (usize, usize),
    // pub section_headers: Vec<ProgramHeader>,
}

impl File {
    const MAGIC: &'static [u8] = &[0x7f, b'E', b'L', b'F'];

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
                prog_header_info: (psize, pcount),
                sect_header_info: (ssize, scount),
            },
        ))
    }

    pub fn parse_or_print_error(input: parse::Input) -> Option<Self> {
        match Self::parse(input) {
            Ok((_, file)) => Some(file),
            Err(nom::Err::Failure(e)) | Err(nom::Err::Error(e)) => {
                eprintln!("Failed parsing input!");
                for (input, err) in e.errors {
                    eprintln!("{:?} at:", err);
                    eprintln!("{:?}", HexDump(input));
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
