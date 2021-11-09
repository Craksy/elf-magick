pub type Input<'a> = &'a [u8];
pub type Result<'a, O> = nom::IResult<Input<'a>, O, nom::error::VerboseError<Input<'a>>>;

#[macro_export]
macro_rules! impl_parse_for_enum {
    ($type:ident, $number_parser: ident) => {
        impl $type {
            pub fn parse(input: parse::Input) -> parse::Result<Self> {
                let parser = map_res($number_parser, |x| {
                    Self::try_from(x).map_err(|_| ErrorKind::Alt)
                });
                context(stringify!($type), parser)(input)
            }
        }
    };
}

#[macro_export]
macro_rules! impl_parse_for_bitflags {
    ($type: ident, $number_parser: ident) => {
        impl $type {
            pub fn parse(input: parse::Input) -> parse::Result<enumflags2::BitFlags<Self>> {
                let parser = map_res($number_parser, |x| {
                    enumflags2::BitFlags::<Self>::from_bits(x).map_err(|_| ErrorKind::Alt)
                });
                context(stringify!($type), parser)(input)
            }
        }
    };
}
