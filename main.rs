#![recursion_limit = "1024"]

#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate nom;
extern crate safemem;

use nom::{le_u8, le_u16, le_u32};
use std::io::prelude::*;
use std::io::{Cursor, Error, ErrorKind};
use std::fs::File;

named!(get_ne_offset<u16>,
	do_parse!(
		tag!("MZ") >>
		take!(58) >>
		ne_offset: le_u16 >>
		( ne_offset )
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
	linker_major_version: u8,
	linker_minor_version: u8,
	entry_table_offset: u16,
	entry_table_length: u16,
	crc: u32,
	flags: NEFlags,
	auto_data_segment_index: u16,
	heap_size: u16,
	stack_size: u16,
	entry_point: u32,
	init_stack_pointer: u32,
	num_segments: u16,
	num_modules: u16,
	names_size: u16,
	segment_table_offset: u16, // bytes, from start of NEHeader
	resource_table_offset: u16,
	names_table_offset: u16,
	module_table_offset: u16,
	import_names_table_offset: u16,
	non_resident_table_offset: u32,
	num_movable_entry_point: u16,
	alignment_shift_count: u16, // 1 << alignment_shift_count = logical sector
	num_resources: u16,
	target_os: u8,
	os2_flags: u8,
	thunk_offset: u16,
	segment_thunk_offset: u16,
	min_code_swap_size: u16,
	win_version_minor: u8,
	win_version_major: u8
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
		linker_major_version: le_u8 >>
		linker_minor_version: le_u8 >>
		entry_table_offset: le_u16 >> // relative to beginning of header
		entry_table_length: le_u16 >> // bytes
		crc: le_u32 >>
		flags: le_u16 >>
		auto_data_segment_index: le_u16 >>
		heap_size: le_u16 >>
		stack_size: le_u16 >>
		entry_point: le_u32 >> // cs:ip
		init_stack_pointer: le_u32 >> // ss:sp
		num_segments: le_u16 >>
		num_modules: le_u16 >>
		names_size: le_u16 >>
		segment_table_offset: le_u16 >>
		resource_table_offset: le_u16 >>
		names_table_offset: le_u16 >>
		module_table_offset: le_u16 >>
		import_names_table_offset: le_u16 >>
		non_resident_table_offset: le_u32 >>
		num_movable_entry_point: le_u16 >>
		alignment_shift_count: le_u16 >>
		num_resources: le_u16 >>
		target_os: le_u8 >>
		os2_flags: le_u8 >>
		thunk_offset: le_u16 >>
		segment_thunk_offset: le_u16 >>
		min_code_swap_size: le_u16 >>
		win_version_minor: le_u8 >>
		win_version_major: le_u8 >>
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
	offset: u16, // logical sector alignment offset from start of file
	length: u16, // bytes, 0 means 64k
	flags: NESegmentFlags,
	min_allocation_size: u16, // bytes, 0 means 64k
}

named!(get_segment_entry<NESegmentEntry>,
	do_parse!(
		offset: le_u16 >>
		length: le_u16 >>
		flags: le_u16 >>
		min_allocation_size: le_u16 >>
		(NESegmentEntry {
			offset,
			length,
			flags: NESegmentFlags::from_bits_truncate(flags),
			min_allocation_size
		})
	)
);

#[derive(Clone, Debug)]
struct NESelfLoadHeader {
	boot_app_offset: u32,
	load_app_seg_offset: u32,
	optloader_code_length: u16,
}

named!(read_selfload_header<NESelfLoadHeader>,
	do_parse!(
		tag!("A0") >>
		le_u16 >> // reserved
		boot_app_offset: le_u32 >>
		load_app_seg_offset: le_u32 >>
		le_u32 >> // reserved
		le_u32 >> // mem alloc
		le_u32 >> // ordinal resolve
		le_u32 >> // exit
		count!(le_u16, 4) >> // reserved
		le_u32 >> // set owner
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
		data: take!(length) >>
		(String::from_utf8_lossy(data).to_string())
	)
);

#[derive(Clone, Debug)]
enum NESegmentRelocationSourceKind {
	LoByte  = 0,
	Segment = 2,
	FarAddr = 3,
	Offset  = 5
}

#[derive(Clone, Debug)]
enum NESegmentRelocationTarget {
	InternalRef {
		segment: u8,
		offset: u16
	},
	ImportName {
		module_index: u16,
		name_offset: u16, // into imported names table
	},
	ImportOrdinal {
		module_index: u16,
		ordinal: u16,
	},
	OsFixup {
		kind: u16,
	}
}

#[derive(Clone, Debug)]
struct NESegmentRelocation {
	kind: NESegmentRelocationSourceKind,
	offset: u16,
	additive: bool,
	target: NESegmentRelocationTarget,
}

named!(read_relocation<NESegmentRelocation>,
	do_parse!(
		kind: le_u8 >>
		flags: le_u8 >>
		offset: le_u16 >>
		data1: le_u16 >> // TODO: wrong for ADDITIVE flag
		data2: le_u16 >>
		(NESegmentRelocation {
			kind: match kind {
				0 => NESegmentRelocationSourceKind::LoByte,
				2 => NESegmentRelocationSourceKind::Segment,
				3 => NESegmentRelocationSourceKind::FarAddr,
				5 => NESegmentRelocationSourceKind::Offset,
				_ => { panic!("Unknown relocation type {}", kind); }
			},
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

named!(detect_offsets<(u16, u16)>,
	do_parse!(
		take!(11) >> // TODO: figure out how to make take_until_and_consume use a byte array
		tag!(/* mov si, */ [b'\xbe']) >>
		source_offset: le_u16 >>
		tag!(/* mov di, */ [b'\xbf']) >>
		target_offset: le_u16 >>
		((source_offset, target_offset))
	)
);

fn read_relocations(mut data: &[u8]) -> Result<Vec<NESegmentRelocation>, nom::Err<&[u8]>> {
	let ret = le_u16(data)?;
	data = ret.0;
	let count = ret.1;
	let mut relocations: Vec<NESegmentRelocation> = Vec::with_capacity(count as usize);
	for _ in 0..count {
		let ret = read_relocation(&data)?;
		data = ret.0;
		relocations.push(ret.1);
	}
	Ok(relocations)
}

fn decrypt_load_app_seg(cseg0: &mut [u8], source_offset: u16, target_offset: u16) {
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

fn fix_file(filename: &str) -> Result<(), Error> {
	let mut file = File::open(&filename)?;
	let mut executable: Vec<u8> = Vec::with_capacity(file.metadata()?.len() as usize);
	file.read_to_end(&mut executable)?;

	let ne_offset = match get_ne_offset(&executable) {
		Ok((_, offset)) => {
			assert!((offset as usize) < executable.len());
			offset
		},
		Err(_) => {
			return Err(Error::new(ErrorKind::InvalidData, "Not a valid MZ executable"));
		}
	};

	let ne_executable = &executable[ne_offset as usize..];

	let ne_header = match read_ne_header(&ne_executable) {
		Ok((_, header)) => header,
		Err(_) => {
			return Err(Error::new(ErrorKind::InvalidData, "Not a valid NE executable"));
		}
	};

	if !ne_header.flags.contains(NEFlags::SELF_LOAD) {
		return Err(Error::new(ErrorKind::InvalidData, "Not a self-loading executable"));
	}

	// println!("{:?}", ne_header);

	let module_name = match read_pascal_string(&executable[(ne_header.non_resident_table_offset as usize)..]) {
		Ok((_, name)) => name,
		Err(_) => {
			return Err(Error::new(ErrorKind::InvalidData, "Invalid executable name"));
		}
	};

	let mut ne_segments: Vec<NESegmentEntry> = Vec::with_capacity(ne_header.num_segments as usize);

	let mut ne_segment_table = &ne_executable[ne_header.segment_table_offset as usize..];
	for _ in 0..ne_header.num_segments {
		let (remainder, mut entry) = get_segment_entry(&ne_segment_table).unwrap();
		entry.offset <<= ne_header.alignment_shift_count;
		ne_segments.push(entry);
		ne_segment_table = remainder;
	}

	let cseg0_header = &ne_segments[0];
	let cseg0 = &mut executable[cseg0_header.offset as usize..];

	// println!("{:?}", cseg0_header);

	let ne_selfload_header = match read_selfload_header(&cseg0) {
		Ok((_, header)) => header,
		Err(_) => {
			return Err(Error::new(ErrorKind::InvalidData, "Invalid self-loading executable header"));
		}
	};

	// println!("{:?}", ne_selfload_header);

	if cseg0_header.flags.contains(NESegmentFlags::HAS_RELOC) {
		let cseg0_reloc = &cseg0[cseg0_header.length as usize..];
		let relocations = match read_relocations(&cseg0_reloc) {
			Ok(relocations) => relocations,
			Err(_) => {
				return Err(Error::new(ErrorKind::InvalidData, "Failed to read relocation table"));
			}
		};
		// println!("{:?}", relocations);
	}

	let boot_app = &cseg0[(ne_selfload_header.boot_app_offset & 0xff) as usize..];

	let offsets_bytecode = match detect_optloader(&boot_app) {
		Ok((bytecode, copyright)) => {
			println!("Found {}", copyright);
			bytecode
		},
		Err(_) => {
			return Err(Error::new(ErrorKind::InvalidData, "Failed to find Optloader copyright"));
		}
	};

	println!("Unpacking {}", module_name);

	let (copy_from, copy_to) = match detect_offsets(&offsets_bytecode) {
		Ok((_, offsets)) => (offsets.0, offsets.1 - ne_selfload_header.optloader_code_length),
		Err(_) => {
			return Err(Error::new(ErrorKind::InvalidData, "Failed to find code offsets"));
		}
	};

	safemem::copy_over(cseg0, copy_from.into(), copy_to.into(), ne_selfload_header.optloader_code_length.into());

	decrypt_load_app_seg(cseg0, (ne_selfload_header.load_app_seg_offset & 0xffff) as u16, copy_to + 1);

	std::fs::write(String::from(filename) + ".out", &executable)?;

	Ok(())
}

fn main() {
	let args: Vec<_> = std::env::args().collect();
	if args.len() < 2 {
		println!("Usage: {} <packed executable>", args[0]);
		return;
	}

	fix_file(&args[1]).unwrap();
}
