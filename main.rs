#![recursion_limit = "1024"]

mod decompressor;
mod neexe;
#[macro_use] mod util;

use byteorder::{ByteOrder, LittleEndian as LE};
use decompressor::{Decompressor, Op};
use neexe::*;
use nom::{do_parse, le_u16, le_u32, named, named_args, tag, take_until, take_until_and_consume};
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::fs::File;
use util::read_pascal_string;

#[derive(Clone, Debug)]
struct OptloaderHeader {
	ne_header:   NESelfLoadHeader,
	code_length: u16,
}

named!(read_optloader_header<OptloaderHeader>,
	do_parse!(
		ne_header:   read_selfload_header >>
		             le_u32 >> // ALLOCSTODSALIAS
		             le_u16 >> // __AHINCR
		code_length: le_u16 >>
		(OptloaderHeader {
			ne_header,
			code_length
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

#[derive(Debug)]
struct OptOffsets {
	copy_from_offset:       u16,
	copy_to_offset:         u16,
	copy_length:            u16,
	decompress_from_offset: u16,
	decompress_to_offset:   u16,
}

const X86_MOV_SI: u8 = b'\xbe';
const X86_MOV_DI: u8 = b'\xbf';
named_args!(get_offsets(code_size: u16)<OptOffsets>,
	do_parse!(
		                      take_until_and_consume!(&[X86_MOV_SI][..]) >>
		copy_from_offset:     le_u16 >>
		                      tag!([X86_MOV_DI]) >>
		copy_to_offset_end:   le_u16 >>
		                      take_until_and_consume!(&[X86_MOV_DI][..]) >>
		decompress_to_offset: le_u16 >>
		(OptOffsets {
			copy_from_offset,
			copy_to_offset: copy_to_offset_end - code_size,
			copy_length: code_size,
			decompress_from_offset: copy_to_offset_end - code_size + 1,
			decompress_to_offset
		})
	)
);

fn unpack_load_app_seg(output: &mut [u8], offsets: OptOffsets) -> Result<usize, Error> {
	// TODO: Instead of creating a duplicate copy of the input data, look for
	// negative offsets when doing CopyBytes and translate them into the correct
	// position in the input slice?
	let input = {
		let mut input: Vec<u8> = Vec::from(&output[..]);
		// TODO: Why is the last byte not being copied without the +1?
		safemem::copy_over(&mut input, offsets.copy_from_offset as usize, offsets.copy_to_offset as usize, offsets.copy_length as usize + 1);
		input
	};

	// println!("{:x?}", &input[offsets.decompress_from_offset as usize..]);

	let mut decompressor = Decompressor::new(&input[offsets.decompress_from_offset as usize..])?;
	let mut output_index = offsets.decompress_to_offset as usize;

	// offset = (offset << 8) | *(u8*)si++;
	// ax = si;
	// si = di-offset-1;
	// while (count--) *(u8*)di++ = *(u8*)si++;
	// si = ax;

	loop {
		let op = decompressor.next_op()?;
		// println!("{:x?}", op);
		match op {
			Op::Noop => {
				continue;
			},
			Op::Literal(value) => {
				output[output_index] = value;
				output_index += 1;
			},
			Op::Terminate => {
				break;
			},
			Op::CopyBytes{ offset, count } => {
				safemem::copy_over(output, output_index - (offset as usize) - 1, output_index, count.into());
				output_index += count as usize;
			}
		}
	}
	Ok(output_index)
}

fn fix_file(in_filename: &str, out_filename: &str) -> Result<(usize, usize), Error> {
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
		let ne_non_resident_table = &input[ne_header.non_resident_table_offset as usize..];
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

	// println!("{:#?}", &resource_table);

	let entry_table = {
		let ne_entry_table = &ne_executable[ne_header.entry_table_offset as usize..ne_header.entry_table_offset as usize + ne_header.entry_table_length as usize];
		try_parse!(get_entry_points(&ne_entry_table), "Invalid entry table")
	};

	println!("{:#?}", &entry_table);

	let cseg0_header = &segments[0];
	let cseg0 = &input[cseg0_header.offset as usize..];

	// println!("{:#?}", cseg0_header);

	let optloader_header = try_parse!(read_optloader_header(&cseg0), "Invalid self-loading executable header");

	// println!("{:#?}", ne_selfload_header);

	// TODO: Discard this if it actually is not necessary for fixing up the
	// executable
	if cseg0_header.flags.contains(NESegmentFlags::HAS_RELOC) {
		let cseg0_reloc = &cseg0[cseg0_header.length as usize..];
		let _relocations = try_parse!(read_relocations(&cseg0_reloc), "Failed to read relocation table");
		// println!("{:#?}", relocations);
	}

	let boot_app = &cseg0[(optloader_header.ne_header.boot_app_offset & 0xff) as usize..];

	let offsets_bytecode = match detect_optloader(&boot_app) {
		Ok((bytecode, copyright)) => {
			println!("Found {}", copyright);
			bytecode
		},
		Err(_) => err!("Failed to find Optloader copyright")
	};

	println!("Unpacking {}", module_name);

	// copy executable header
	let mut out: Vec<u8> = Vec::new();
	out.extend_from_slice(&input[0..segments[0].offset as usize]);

	// eventually this will be in a loop
	let mut size_delta = (segments[0].alloc_size - segments[0].length) as usize;
	out.extend_from_slice(&input[segments[0].offset as usize..(segments[0].offset as usize + segments[0].length as usize)]);
	out.resize(out.len() + size_delta, 0);

	let offsets = try_parse!(get_offsets(&offsets_bytecode, optloader_header.code_length), "Failed to find code offsets");
	unpack_load_app_seg(&mut out[segments[0].offset as usize..], offsets)?;

	let mut remainder = &input[segments[0].offset as usize + segments[0].length as usize..];

	if segments[0].flags.contains(NESegmentFlags::HAS_RELOC) {
		const RELOC_COUNT_SIZE: u16 = 2;
		const RELOC_RECORD_SIZE: u16 = 8;
		let reloc_table = remainder;
		let reloc_size = LE::read_u16(reloc_table) * RELOC_RECORD_SIZE + RELOC_COUNT_SIZE;
		out.extend_from_slice(&reloc_table[0..reloc_size as usize]);
		remainder = &input[segments[1].offset as usize..];
	}

	let alignment = 1 << ne_header.alignment_shift_count;

	let mut alignment_bytes = out.len() % alignment;
	if alignment_bytes != 0 {
		alignment_bytes = alignment - alignment_bytes;
		out.resize(out.len() + (alignment_bytes as usize), 0);
		size_delta += alignment_bytes;
	}

	size_delta >>= ne_header.alignment_shift_count;

	out.extend_from_slice(remainder);

	// LE::write_u16(&mut out[(ne_offset as usize + /* num segments */ 28)..], 1);
	LE::write_u16(&mut out[(ne_offset as usize + ne_header.segment_table_offset as usize) + 2..], segments[0].alloc_size as u16);

	{
		const ENTRY_SIZE: usize = 8;
		let mut segment_table = &mut out[ne_offset as usize + ne_header.segment_table_offset as usize + /* skip to first entry */ ENTRY_SIZE..];
		for _ in 1..ne_header.num_segments {
			let new_offset = LE::read_u16(&segment_table) + size_delta as u16;
			LE::write_u16(&mut segment_table, new_offset);
			segment_table = &mut segment_table[ENTRY_SIZE..];
		}
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
	// - Clear selfload flag
	// - Rewrite segment table
	// - Rewrite resource table
	// - For each segment:
	//   - Decompress code into new code segment
	//   - Copy reloc trailer, if it exists
	//   - Add alignment padding
	// - Copy executable trailer data
	// - Rewrite offset to trailer data

	std::fs::write(out_filename, &out)?;

	Ok((input.len(), out.len()))
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
		Ok((in_size, out_size)) => {
			println!("Successfully unpacked {} to {} ({} -> {} bytes)", &in_filename, &out_filename, in_size, out_size);
		},
		Err(e) => {
			println!("Failed to unpack {}: {}", &in_filename, &e);
			std::process::exit(1);
		}
	};
}
