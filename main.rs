#![recursion_limit = "1024"]

#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate enum_primitive;
extern crate num;
#[macro_use]
extern crate nom;
extern crate safemem;

use byteorder::{ByteOrder, LittleEndian as LE};
use nom::{le_u8, le_u16, le_u32};
use num::FromPrimitive;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::fs::File;

named!(get_ne_offset<u16>,
	do_parse!(
		           tag!("MZ") >>
		           take!(58) >>
		ne_offset: le_u16 >>
		(ne_offset)
	)
);

bitflags!(struct NEFlags: u16 {
	const SINGLE_DATA   = 0x0001;
	const MULTIPLE_DATA = 0x0002;
	const WIN32S        = 0x0010;
	const FULLSCREEN    = 0x0100;
	const CONSOLE       = 0x0200;
	const GUI           = 0x0300;
	const SELF_LOAD     = 0x0800;
	const LINKER_ERROR  = 0x2000;
	const CALL_WEP      = 0x4000;
	const LIB_MODULE    = 0x8000;
});

#[derive(Clone, Debug)]
struct NEHeader {
	linker_major_version:      u8,
	linker_minor_version:      u8,
	entry_table_offset:        u16,
	entry_table_length:        u16,
	crc:                       u32,
	flags:                     NEFlags,
	auto_data_segment_index:   u16,
	heap_size:                 u16,
	stack_size:                u16,
	entry_point:               u32,
	init_stack_pointer:        u32,
	num_segments:              u16,
	num_modules:               u16,
	names_size:                u16,
	segment_table_offset:      u16, // bytes, from start of NEHeader
	resource_table_offset:     u16,
	names_table_offset:        u16,
	module_table_offset:       u16,
	import_names_table_offset: u16,
	non_resident_table_offset: u32,
	num_movable_entry_point:   u16,
	alignment_shift_count:     u16, // 1 << alignment_shift_count = logical sector
	num_resources:             u16,
	target_os:                 u8,
	os2_flags:                 u8,
	thunk_offset:              u16,
	segment_thunk_offset:      u16,
	min_code_swap_size:        u16,
	win_version_minor:         u8,
	win_version_major:         u8,
}

bitflags!(struct NESegmentFlags: u16 {
	const CODE      = 0x0000;
	const DATA      = 0x0001;
	const MOVEABLE  = 0x0010;
	const PRELOAD   = 0x0040;
	const HAS_RELOC = 0x0100;
	const PRIORITY  = 0xF000;
});

named!(read_ne_header<NEHeader>,
	do_parse!(
		                           tag!("NE") >>
		linker_major_version:      le_u8 >>
		linker_minor_version:      le_u8 >>
		entry_table_offset:        le_u16 >> // relative to beginning of header
		entry_table_length:        le_u16 >> // bytes
		crc:                       le_u32 >>
		flags:                     le_u16 >>
		auto_data_segment_index:   le_u16 >>
		heap_size:                 le_u16 >>
		stack_size:                le_u16 >>
		entry_point:               le_u32 >> // cs:ip
		init_stack_pointer:        le_u32 >> // ss:sp
		num_segments:              le_u16 >>
		num_modules:               le_u16 >>
		names_size:                le_u16 >>
		segment_table_offset:      le_u16 >>
		resource_table_offset:     le_u16 >>
		names_table_offset:        le_u16 >>
		module_table_offset:       le_u16 >>
		import_names_table_offset: le_u16 >>
		non_resident_table_offset: le_u32 >>
		num_movable_entry_point:   le_u16 >>
		alignment_shift_count:     le_u16 >>
		num_resources:             le_u16 >>
		target_os:                 le_u8 >>
		os2_flags:                 le_u8 >>
		thunk_offset:              le_u16 >>
		segment_thunk_offset:      le_u16 >>
		min_code_swap_size:        le_u16 >>
		win_version_minor:         le_u8 >>
		win_version_major:         le_u8 >>
		(NEHeader {
			linker_major_version,
			linker_minor_version,
			entry_table_offset,
			entry_table_length,
			crc,
			flags: NEFlags::from_bits_truncate(flags),
			auto_data_segment_index,
			heap_size,
			stack_size,
			entry_point,
			init_stack_pointer,
			num_segments,
			num_modules,
			names_size,
			segment_table_offset,
			resource_table_offset,
			names_table_offset,
			module_table_offset,
			import_names_table_offset,
			non_resident_table_offset,
			num_movable_entry_point,
			alignment_shift_count,
			num_resources,
			target_os,
			os2_flags,
			thunk_offset,
			segment_thunk_offset,
			min_code_swap_size,
			win_version_minor,
			win_version_major
		})
	)
);

#[derive(Clone, Debug)]
struct NESegmentEntry {
	offset:        u32, // bytes
	length:        u32, // bytes
	flags:         NESegmentFlags,
	alloc_size:    u32, // bytes
}

named_args!(get_segments(offset_shift: u16, num_segments: u16)<Vec<NESegmentEntry> >,
	count!(
		do_parse!(
			offset:     le_u16 >>
			length:     le_u16 >>
			flags:      le_u16 >>
			alloc_size: le_u16 >>
			(NESegmentEntry {
				offset:        (offset as u32) << offset_shift,
				length:        if length == 0 { 0x10000 } else { length.into() },
				flags:         NESegmentFlags::from_bits_truncate(flags),
				alloc_size:    if alloc_size == 0 { 0x10000 } else { alloc_size.into() }
			})
		), num_segments as usize
	)
);

bitflags!(struct NEResourceFlags: u16 {
	const MOVEABLE = 0x10;
	const PURE     = 0x20;
	const PRELOAD  = 0x40;
});

enum_from_primitive! {
	#[derive(Clone, Debug)]
	enum NEPredefinedResourceKind {
		Cursor           = 1,
		Bitmap           = 2,
		Icon             = 3,
		Menu             = 4,
		Dialog           = 5,
		StringTable      = 6,
		FontDirectory    = 7,
		FontResource     = 8,
		AcceleratorTable = 9,
		RawData          = 10,
		MessageTable     = 11,
		GroupCursor      = 12,
		GroupIcon        = 14,
		Version          = 16,
		DlgInclude       = 17,
		PlugPlay         = 19,
		VXD              = 20,
		AnimatedCursor   = 21,
		AnimatedIcon     = 22,
		HTML             = 23,
		Manifest         = 24,
	}
}

#[derive(Clone, Debug)]
enum NEResourceKind {
	Predefined(NEPredefinedResourceKind),
	Integer(u16),
	String(String),
}

#[derive(Clone, Debug)]
enum NEResourceId {
	Integer(u16),
	String(String),
}

#[derive(Clone, Debug)]
struct NEResourceEntry {
	offset: u32, // bytes
	length: u32, // bytes
	flags:  NEResourceFlags,
	id:     NEResourceId,
}

#[derive(Clone, Debug)]
struct NEResourceKindEntry {
	kind:      NEResourceKind,
	resources: Vec<NEResourceEntry>,
}

#[derive(Clone, Debug)]
struct NEResourceTable {
	alignment_shift_count: u16,
	resource_kinds: Vec<NEResourceKindEntry>,
}

fn convert_resource_kind(resource_table: &[u8], kind: u16) -> NEResourceKind {
	if kind & 0x8000 == 0x8000 {
		match NEPredefinedResourceKind::from_u16(kind & 0x7fff) {
			Some(kind) => NEResourceKind::Predefined(kind),
			None => NEResourceKind::Integer(kind & 0x7fff)
		}
	} else {
		NEResourceKind::String(read_pascal_string(&resource_table[kind as usize..]).unwrap().1)
	}
}

named_args!(read_resource<'a>(resource_table: &'a [u8], offset_shift: u16)<NEResourceEntry>,
	do_parse!(
		offset:        le_u16 >> // in sectors
		length:        le_u16 >> // in sectors
		flags:         le_u16 >>
		id:            le_u16 >>
		/* reserved */ le_u32 >>
		(NEResourceEntry {
			offset: (offset as u32) << offset_shift,
			length: (length as u32) << offset_shift,
			flags: NEResourceFlags::from_bits_truncate(flags),
			id: if id & 0x8000 == 0x8000 {
				NEResourceId::Integer(id & 0x7fff)
			} else {
				NEResourceId::String(read_pascal_string(&resource_table[id as usize..]).unwrap().1)
			}
		})
	)
);

named_args!(read_resource_kind<'a>(resource_table: &'a [u8], offset_shift: u16)<NEResourceKindEntry>,
	do_parse!(
		kind:          le_u16 >>
		num_resources: le_u16 >>
		/* reserved */ take!(4) >>
		resources:     count!(apply!(read_resource, resource_table, offset_shift), num_resources as usize) >>
		(NEResourceKindEntry {
			kind: convert_resource_kind(resource_table, kind),
			resources
		})
	)
);

fn get_resource_table(input: &[u8]) -> nom::IResult<&[u8], NEResourceTable> {
	do_parse!(input,
		alignment_shift_count: le_u16 >>
		resource_kinds:        many_till!(apply!(read_resource_kind, input, alignment_shift_count), tag!("\0\0")) >>
		(NEResourceTable {
			alignment_shift_count,
			resource_kinds: resource_kinds.0
		})
	)
}

#[derive(Clone, Debug)]
struct NESelfLoadHeader {
	boot_app_offset:       u32,
	load_app_seg_offset:   u32,
	optloader_code_length: u16,
}

named!(read_selfload_header<NESelfLoadHeader>,
	do_parse!(
		                       tag!("A0") >>
		                       le_u16 >> // reserved
		boot_app_offset:       le_u32 >>
		load_app_seg_offset:   le_u32 >>
		                       le_u32 >> // reserved
		                       le_u32 >> // mem alloc
		                       le_u32 >> // ordinal resolve
		                       le_u32 >> // exit
		                       count!(le_u16, 4) >> // reserved
		                       le_u32 >> // set owner
		// these next fields are optloader-specific
		                       le_u32 >> // ALLOCSTODSALIAS
		                       le_u16 >> // __AHINCR
		optloader_code_length: le_u16 >>
		(NESelfLoadHeader {
			boot_app_offset,
			load_app_seg_offset,
			optloader_code_length
		})
	)
);

named!(read_pascal_string<String>,
	do_parse!(
		length: le_u8 >>
		data:   take!(length) >>
		(String::from_utf8_lossy(data).to_string())
	)
);

enum_from_primitive! {
	#[derive(Clone, Debug)]
	enum NESegmentRelocationSourceKind {
		LoByte  = 0,
		Segment = 2,
		FarAddr = 3,
		Offset  = 5,
	}
}

#[derive(Clone, Debug)]
enum NESegmentRelocationTarget {
	InternalRef {
		segment: u8,
		offset:  u16,
	},
	ImportName {
		module_index: u16,
		name_offset:  u16, // into imported names table
	},
	ImportOrdinal {
		module_index: u16,
		ordinal:      u16,
	},
	OsFixup {
		kind: u16,
	}
}

#[derive(Clone, Debug)]
struct NESegmentRelocation {
	kind:     NESegmentRelocationSourceKind,
	offset:   u16,
	additive: bool,
	target:   NESegmentRelocationTarget,
}

named!(read_relocation<NESegmentRelocation>,
	do_parse!(
		kind:   le_u8 >>
		flags:  le_u8 >>
		offset: le_u16 >>
		data1:  le_u16 >> // TODO: wrong for ADDITIVE flag
		data2:  le_u16 >>
		(NESegmentRelocation {
			kind: NESegmentRelocationSourceKind::from_u8(kind).expect(&format!("Unknown relocation type {}", kind)),
			offset,
			additive: (flags & 4) == 4,
			target: match flags & 3 {
				0 => NESegmentRelocationTarget::InternalRef {
					segment: (data1 & 0xff) as u8,
					offset: data2
				},
				1 => NESegmentRelocationTarget::ImportOrdinal {
					module_index: data1,
					ordinal: data2
				},
				2 => NESegmentRelocationTarget::ImportName {
					module_index: data1,
					name_offset: data2
				},
				3 => NESegmentRelocationTarget::OsFixup {
					kind: data1
				},
				_ => { panic!("Unknown relocation target {}", flags & 3); }
			}
		})
	)
);

named!(detect_optloader<String>,
	do_parse!(
		      take_until!("OPTLOADER") >>
		text: take_until_and_consume!("\0") >>
		(String::from_utf8_lossy(text).to_string())
	)
);

const X86_MOV_SI: u8 = b'\xbe';
const X86_MOV_DI: u8 = b'\xbf';
named!(detect_offsets<(u16, u16)>,
	do_parse!(
		               take_until!(&[X86_MOV_SI][..]) >>
		               tag!([X86_MOV_SI]) >>
		source_offset: le_u16 >>
		               tag!([X86_MOV_DI]) >>
		target_offset: le_u16 >>
		((source_offset, target_offset))
	)
);

named!(read_relocations<Vec<NESegmentRelocation> >,
	do_parse!(
		length:      le_u16 >>
		relocations: count!(call!(read_relocation), length as usize) >>
		(relocations)
	)
);

fn unpack_load_app_seg(cseg0: &mut [u8], source_offset: u16, target_offset: u16) {
	// bytes are LSB first, bits MSB first, read in blocks of 2 bytes

	// 1 -> *(u8*)di++ = *(u8*)si++; continue;
	// 000 -> offset = 0, count = 2, WRITE
	// 001 -> count = 3, FIND_OFFSET
	// 0100 -> count = 4, FIND_OFFSET
	// 0101 -> count = 5, FIND_OFFSET
	// 01100 -> count = 6, FIND_OFFSET
	// 01101 -> count = 7, FIND_OFFSET
	// 01110 -> count = 8 + read_bits(2), FIND_OFFSET
	// 011110 -> count = 12 + read_bits(3), FIND_OFFSET
	// 011111 -> count = *(u8*)si++; if (count < 0x81) go FIND_OFFSET; else if (count != 0x81) break; else continue;

	// FIND_OFFSET
	// 00 -> offset = 0, WRITE
	// 010 -> offset = 1, WRITE
	// 011 -> offset = 2 + read_bits(1), WRITE
	// 100 -> offset = 4 + read_bits(2), WRITE
	// 101 -> offset = 8 + read_bits(3), WRITE
	// 110 -> offset = 16 + read_bits(4), WRITE
	// 1110 -> offset = 32 + read_bits(4), WRITE
	// 11110 -> offset = 48 + read_bits(4), WRITE
	// 11111 -> offset = 64 + read_bits(6), WRITE

	// WRITE
	// offset = (offset << 8) | *(u8*)si++;
	// ax = si;
	// si = di-offset-1;
	// while (count--) *(u8*)di++ = *(u8*)si++;
	// si = ax;
}

macro_rules! err (
	($reason: expr) => (
		return Err(Error::new(ErrorKind::InvalidData, $reason));
	)
);

macro_rules! try_parse (
	($result: expr, $reason: expr) => (match $result {
		Ok((_, result)) => result,
		Err(_) => { err!($reason) }
	})
);

fn fix_file(in_filename: &str, out_filename: &str) -> Result<(), Error> {
	let input = {
		let mut file = File::open(&in_filename)?;
		let mut input: Vec<u8> = Vec::with_capacity(file.metadata()?.len() as usize);
		file.read_to_end(&mut input)?;
		input
	};

	let ne_offset = try_parse!(get_ne_offset(&input), "Not an MZ executable");
	let ne_executable = &input[ne_offset as usize..];

	let ne_header = try_parse!(read_ne_header(&ne_executable), "Not an NE executable");

	if !ne_header.flags.contains(NEFlags::SELF_LOAD) {
		return Err(Error::new(ErrorKind::InvalidData, "Not a self-loading executable"));
	}

	println!("{:#?}", ne_header);

	let module_name = {
		let ne_non_resident_table = &input[(ne_header.non_resident_table_offset as usize)..];
		try_parse!(read_pascal_string(&ne_non_resident_table), "Invalid executable name")
	};

	let segments = {
		let ne_segment_table = &ne_executable[ne_header.segment_table_offset as usize..];
		try_parse!(get_segments(
			&ne_segment_table,
			ne_header.alignment_shift_count,
			ne_header.num_segments
		), "Invalid segment table")
	};

	println!("{:#?}", &segments);

	let resource_table = {
		let ne_resource_table = &ne_executable[ne_header.resource_table_offset as usize..];
		try_parse!(get_resource_table(&ne_resource_table), "Invalid resource table")
	};

	println!("{:#?}", &resource_table);

	let cseg0_header = &segments[0];
	let cseg0 = &input[cseg0_header.offset as usize..];

	// println!("{:#?}", cseg0_header);

	let ne_selfload_header = try_parse!(read_selfload_header(&cseg0), "Invalid self-loading executable header");

	// println!("{:#?}", ne_selfload_header);

	// TODO: Discard this if it actually is not necessary for fixing up the
	// executable
	if cseg0_header.flags.contains(NESegmentFlags::HAS_RELOC) {
		let cseg0_reloc = &cseg0[cseg0_header.length as usize..];
		let _relocations = try_parse!(read_relocations(&cseg0_reloc), "Failed to read relocation table");
		// println!("{:#?}", relocations);
	}

	let boot_app = &cseg0[(ne_selfload_header.boot_app_offset & 0xff) as usize..];

	let offsets_bytecode = match detect_optloader(&boot_app) {
		Ok((bytecode, copyright)) => {
			println!("Found {}", copyright);
			bytecode
		},
		Err(_) => err!("Failed to find Optloader copyright")
	};

	println!("Unpacking {}", module_name);

	let (copy_from, copy_to) = {
		let offsets = try_parse!(detect_offsets(&offsets_bytecode), "Failed to find code offsets");
		(offsets.0, offsets.1 - ne_selfload_header.optloader_code_length)
	};

	// copy executable headers
	let mut out: Vec<u8> = Vec::new();
	out.extend(&input[0..segments[0].offset as usize]);

	// rewrite segment table
	{

	}

	// rewrite_segment_table(&mut out[(ne_offset + ne_header.segment_table_offset) as usize..]);
	// rewrite_resource_table(&mut out[(ne_offset + ne_header.resource_table_offset) as usize..]);

	// {
	// 	const LENGTH_FIELD: usize = 2;
	// 	const ENTRY_SIZE: usize = 8;
	// 	let mut out_segment_table = ;
	// 	LE::write_u16(&mut out_segment_table[LENGTH_FIELD..], segments[0].alloc_size as u16);
	// 	out_segment_table = &mut out_segment_table[ENTRY_SIZE..];
	// }

	// TODO:
	// - Copy over headers
	// - Clear selfload flag
	// - Rewrite segment table
	// - Rewrite resource table
	// - For each segment:
	//   - Decompress code into new code segment
	//   - Copy reloc trailer, if it exists
	//   - Add alignment padding
	// - Copy executable trailer data
	// - Rewrite offset to trailer data

	//safemem::copy_over(cseg0, copy_from.into(), copy_to.into(), ne_selfload_header.optloader_code_length.into());
	//unpack_load_app_seg(cseg0, (ne_selfload_header.load_app_seg_offset & 0xffff) as u16, copy_to + 1);

	// std::fs::write(String::from(filename) + ".out", &executable)?;

	Ok(())
}

fn main() {
	let (in_filename, out_filename) = {
		let args: Vec<_> = std::env::args().collect();
		if args.len() < 2 {
			println!("Usage: {} <packed executable> [<output filename>]", &args[0]);
			std::process::exit(1);
		}

		let out_file = if args.len() > 2 { args[2].clone() } else { args[1].clone() + ".out" };
		(args[1].clone(), out_file)
	};

	match fix_file(&in_filename, &out_filename) {
		Ok(_) => { println!("Successfully unpacked {} to {}", &in_filename, &out_filename); },
		Err(e) => {
			println!("Failed to unpack {}: {}", &in_filename, &e);
			std::process::exit(1);
		}
	};
}
