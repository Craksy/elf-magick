use derive_more::*;
use derive_try_from_primitive::TryFromPrimitive;
use enumflags2::*;
use nom::{
    combinator::{map, map_res, verify},
    error::{context, ErrorKind},
    multi::many_till,
    number::complete::{le_u16, le_u32, le_u64},
    sequence::tuple,
};
use std::{
    convert::TryFrom,
    fmt::{self, Debug},
    ops::Range,
};

use crate::{impl_parse_for_bitflags, impl_parse_for_enum, parse};

use carpenter::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Type {
    None = 0x0,
    Rel,
    Exec,
    Dyn,
    Core,
    Proc = 0xff00,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Machine {
    X86 = 0x03,
    X86_64 = 0x3e,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[rustfmt::skip]
pub enum SegmentType {
    Null        = 0x0,
    Load        = 0x1,
    Dynamic     = 0x2,
    Interp      = 0x3,
    Note        = 0x4,
    ShLib       = 0x5,
    ProgHeader  = 0x6,
    TLS         = 0x7,
    LoOS        = 0x6000_0000,
    HiOS        = 0x6fff_ffff,
    LoProc      = 0x7000_0000,
    HiProc      = 0x7fff_ffff,
    GnuEhFrame  = 0x6474_e550,
    GnuStack    = 0x6474_e551,
    GnuRelRo    = 0x6474_e552,
    GnuProperty = 0x6474_e553,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, BitFlags)]
pub enum SegmentFlags {
    Execute = 0x1,
    Write = 0x2,
    Read = 0x4,
}
pub struct SegmentBits(BitFlags<SegmentFlags>);

#[derive(Debug)]
pub enum SegmentContent {
    Unknown,
    Dynamic(Vec<DynamicEntry>),
}

#[derive(Debug, PrettyTable)]
pub struct DynamicEntry {
    pub tag: DynamicTag,
    pub addr: Addr,
}

#[repr(u64)]
#[derive(Debug, PartialEq, Eq, TryFromPrimitive)]
#[rustfmt::skip]
pub enum DynamicTag {
    Null           = 0,
    Needed         = 1,
    PltRelSz       = 2,
    PltGot         = 3,
    Hash           = 4,
    StrTab         = 5,
    SymTab         = 6,
    Rela           = 7,
    RelaSz         = 8,
    RelaEnt        = 9,
    StrSz          = 10,
    SymEnt         = 11,
    Init           = 12,
    FIni           = 13,
    SOName         = 14,
    RPath          = 15,
    Symbolic       = 16,
    Rel            = 17,
    RelSz          = 18,
    RelEnt         = 19,
    PltRel         = 20,
    Debug          = 21,
    TextRel        = 22,
    JmpRel         = 23,
    BindNow        = 24,
    InitArray      = 25,
    FiniArray      = 26,
    InitArraysz    = 27,
    FiniArraysz    = 28,
    Runpath        = 29,
    Flags          = 30,
    Encoding       = 31,
    PreinitArray   = 32,
    PreinitArraySz = 33,
    MaxPosTags     = 34,
    LoOS           = 0x60000000,
    HiOS           = 0x6fffffff,
    LoProc         = 0x70000000,
    HiProc         = 0x7fffffff,
    GnuHash        = 0x6ffffef5,
    Flags1         = 0x6ffffffb,
    RelaCount      = 0x6ffffff9,
}

#[derive(PrettyTable)]
pub struct RelaEntry {
    pub offset: Addr,
    pub typ: RelType,
    pub sym: u32,
    pub addend: Addr,
}

#[repr(u32)]
#[derive(Debug, TryFromPrimitive, Clone, Copy, PartialEq, Eq)]
pub enum RelType {
    GlobalData = 6,
    JumpSlot = 7,
    Relative = 8,
}

#[derive(PrettyTable)]
pub struct ProgramHeader {
    pub typ: SegmentType,
    pub flags: SegmentBits,
    pub offset: Addr,
    pub virt_addr: Addr,
    pub phys_addr: Addr,
    pub file_size: Addr,
    pub mem_size: Addr,
    pub align: Addr,
    #[skip]
    pub contents: SegmentContent,
    #[skip]
    pub data: Vec<u8>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Sub, Add)]
pub struct Addr(pub u64);

//------------------------------------------------------------
//-------------------- Implementations -----------------------
//------------------------------------------------------------
impl_parse_for_enum!(Type, le_u16);
impl_parse_for_enum!(Machine, le_u16);
impl_parse_for_enum!(SegmentType, le_u32);
impl_parse_for_enum!(RelType, le_u32);
impl_parse_for_enum!(DynamicTag, le_u64);
impl_parse_for_bitflags!(SegmentFlags, le_u32);

impl std::ops::Deref for SegmentBits {
    type Target = BitFlags<SegmentFlags>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for SegmentBits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            &[
                (SegmentFlags::Read, "R"),
                (SegmentFlags::Write, "W"),
                (SegmentFlags::Execute, "X"),
            ]
            .map(|(f, l)| if self.0.contains(f) { l } else { &"-" })
            .join(" ")
        )
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}
impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = format!("{:08X}", self.0);
        let rest = hex.trim_start_matches('0');
        write!(f, "[2m{}[22m{}", "0".repeat(8 - rest.len()), rest)
    }
}
impl Into<u64> for Addr {
    fn into(self) -> u64 {
        self.0
    }
}
impl Into<usize> for Addr {
    fn into(self) -> usize {
        self.0 as usize
    }
}
impl From<u64> for Addr {
    fn from(n: u64) -> Self {
        Self(n)
    }
}
impl Addr {
    pub fn parse(input: crate::parse::Input) -> crate::parse::Result<Self> {
        map(le_u64, From::from)(input)
    }
}

impl DynamicEntry {
    pub fn parse(input: parse::Input) -> parse::Result<Self> {
        let (input, (tag, addr)) = tuple((DynamicTag::parse, Addr::parse))(input)?;
        Ok((input, Self { tag, addr }))
    }
}

impl RelaEntry {
    pub fn parse(input: parse::Input) -> parse::Result<Self> {
        let (input, (offset, typ, sym, addend)) =
            tuple((Addr::parse, RelType::parse, le_u32, Addr::parse))(input)?;
        Ok((
            input,
            Self {
                offset,
                typ,
                sym,
                addend,
            },
        ))
    }
}

impl ProgramHeader {
    pub fn file_range(&self) -> Range<Addr> {
        self.offset..self.offset + self.file_size
    }

    pub fn mem_range(&self) -> Range<Addr> {
        self.virt_addr..self.virt_addr + self.mem_size
    }

    pub fn parse<'a>(
        full_inp: parse::Input<'a>,
        input: parse::Input<'a>,
    ) -> crate::parse::Result<'a, Self> {
        let (input, (typ, flags, offset, virt_addr, phys_addr, file_size, mem_size, align)) =
            tuple((
                SegmentType::parse,
                SegmentFlags::parse,
                Addr::parse,
                Addr::parse,
                Addr::parse,
                Addr::parse,
                Addr::parse,
                Addr::parse,
            ))(input)?;
        let slice = &full_inp[offset.into()..][..file_size.into()];
        let (_, contents) = match typ {
            SegmentType::Dynamic => map(
                many_till(
                    DynamicEntry::parse,
                    verify(DynamicEntry::parse, |e| e.tag == DynamicTag::Null),
                ),
                |(entries, _nulls)| SegmentContent::Dynamic(entries),
            )(slice)?,
            _ => (slice, SegmentContent::Unknown),
        };

        let res = Self {
            typ,
            flags: SegmentBits(flags),
            offset,
            virt_addr,
            phys_addr,
            file_size,
            mem_size,
            align,
            contents,
            data: slice.to_vec(),
        };
        Ok((input, res))
    }
}
