use encoding::{Encoding, DecoderTrap};
use encoding::all::ISO_8859_1;
use nom::{do_parse, le_u8, named, take};

named!(pub read_pascal_string<String>,
	do_parse!(
		length: le_u8 >>
		data:   take!(length) >>
		(ISO_8859_1.decode(data, DecoderTrap::Replace).unwrap())
	)
);
