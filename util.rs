use encoding::{Encoding, DecoderTrap};
use encoding::all::ISO_8859_1;
use nom::{do_parse, le_u8, named, take};

#[macro_export]
macro_rules! err (
	($reason: expr) => ({
		use std::io::{ErrorKind, Error};
		return Err(Error::new(ErrorKind::InvalidData, $reason));
	})
);

#[macro_export]
macro_rules! try_parse (
	($result: expr, $reason: expr) => (match $result {
		Ok((_, result)) => result,
		Err(_) => { err!($reason) }
	})
);

named!(pub read_pascal_string<String>,
	do_parse!(
		length: le_u8 >>
		data:   take!(length) >>
		(ISO_8859_1.decode(data, DecoderTrap::Replace).unwrap())
	)
);
