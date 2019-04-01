#![recursion_limit = "1024"]

mod decompressor;
mod fixup_converter;
mod neexe;
#[macro_use] mod util;

use byteorder::{ByteOrder, LittleEndian as LE};
use decompressor::{Decompressor, Op};
use fixup_converter::FixupConverter;
use neexe::*;
use nom::{do_parse, le_u16, named, named_args, tag, take_until, take_until_and_consume};
use std::io::prelude::*;
use std::io::Error;
use std::fs::File;

named!(detect_optloader<String>,
	do_parse!(
		      take_until!("OPTLOADER") >>
		text: take_until_and_consume!("\0") >>
		(String::from_utf8_lossy(text).to_string())
	)
);

#[derive(Debug, Clone)]
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

struct OptUnpacker<'a> {
	ne:                &'a NEExecutable<'a>,
	output:            Vec<u8>,
	// segment_table:     &'a [u8],
	// resource_table:    &'a [u8],
	copyright:         String,
	boot_code_offsets: OptOffsets,
	sector_alignment:  usize,
	debug: bool,
}

impl<'a> OptUnpacker<'a> {
	pub fn new(ne: &'a NEExecutable) -> Result<Self, String> {
		let (header, boot_code_size) = match ne.get_selfload_header()? {
			Some((header, extra_header_data)) => (header, LE::read_u16(&extra_header_data[6..])),
			None => { return Err("Not a self-loading executable".to_string()); }
		};

		let (copyright, boot_code_offsets) = {
			let boot_code = &ne.get_segment_data(1)?[(header.boot_app_offset & 0xffff) as usize..];
			match detect_optloader(boot_code) {
				Ok((boot_init_code, copyright)) => {
					(copyright, match get_offsets(boot_init_code, boot_code_size) {
						Ok((_, offsets)) => offsets,
						Err(_) => { return Err("Could not find OPTLOADER boot offsets".to_string()); }
					})
				},
				Err(_) => { return Err("Could not find OPTLOADER copyright".to_string()); }
			}
		};

		let mut output = Vec::with_capacity(ne.get_raw_data().len());
		let header_size = ne.get_segment_header(1)?.offset as usize;
		output.extend_from_slice(&ne.get_raw_data()[0..header_size]);
		// let segment_table = &output[ne.get_header().segment_table_offset as usize..];
		// let resource_table = &output[ne.get_header().resource_table_offset as usize..];

		Ok(OptUnpacker {
			ne,
			output,
			copyright,
			// segment_table,
			// resource_table,
			boot_code_offsets,
			sector_alignment: 1 << ne.get_header().alignment_shift_count,
			debug: false
		})
	}

	fn get_copyright(&self) -> &String {
		&self.copyright
	}

	fn run_decompressor(&mut self, input: &[u8], start_index: usize, offsets: OptOffsets) -> Result<(usize, usize), Error> {
		let mut decompressor = Decompressor::new(&input[offsets.decompress_from_offset as usize..])?;
		let output = &mut self.output[start_index..];
		let mut output_index = offsets.decompress_to_offset as usize;

		if self.debug {
			println!("start@{}", start_index);
		}

		loop {
			let op = decompressor.next_op()?;
			if self.debug {
				println!("{:x?}", op);
			}
			match op {
				Op::Noop => {
					continue;
				},
				Op::Literal(value) => {
					output[output_index] = value;
					output_index += 1;
				},
				Op::Terminate(input_index) => {
					return Ok((offsets.decompress_from_offset as usize + input_index, output_index));
				},
				Op::CopyBytes{ offset, count } => {
					safemem::copy_over(output, output_index - (offset as usize) - 1, output_index, count.into());
					output_index += count as usize;
				}
			}
		}
	}

	fn unpack_boot_segment(&mut self) -> Result<usize, Box<std::error::Error>> {
		let segment_header = self.ne.get_segment_header(1)?;
		let segment_data = self.ne.get_segment_data(1)?;

		let new_segment_header = {
			let mut header = segment_header.clone();
			header.data_size = header.alloc_size;
			header
		};
		self.set_segment_table_entry(1, new_segment_header);

		let offsets = &self.boot_code_offsets;
		// TODO: Instead of creating a duplicate copy of the input data, look
		// for negative offsets when doing CopyBytes and translate them into the
		// correct position in the input slice?
		let input = {
			let mut input: Vec<u8> = Vec::with_capacity(segment_header.alloc_size as usize);
			input.extend_from_slice(segment_data);
			input.resize(segment_header.alloc_size as usize, 0);
			if offsets.copy_length > 0 {
				// TODO: Why is the last byte not being copied without the +1?
				safemem::copy_over(
					&mut input,
					offsets.copy_from_offset as usize,
					offsets.copy_to_offset as usize,
					offsets.copy_length as usize + 1
				);
			}
			input
		};

		let expected_size = self.output.len() + segment_header.alloc_size as usize;
		self.output.extend_from_slice(&input[..offsets.decompress_to_offset as usize]);
		self.output.resize(expected_size, 0);
		let (_, mut decompressed_size) = self.run_decompressor(&input, segment_header.offset as usize, (*offsets).clone())?;
		if segment_header.flags.contains(NESegmentFlags::HAS_RELOC) {
			let fixup_table = &segment_data[segment_header.data_size as usize..];
			self.output.extend_from_slice(fixup_table);
			decompressed_size += fixup_table.len();
		}
		decompressed_size += self.align_output();
		Ok(decompressed_size)
	}

	fn write_to_file(&self, filename: &str) -> Result<(usize, usize), Box<std::error::Error>> {
		std::fs::write(filename, &self.output)?;
		Ok((self.ne.get_raw_data().len(), self.output.len()))
	}

	fn set_segment_table_entry(&mut self, segment_number: u16, data: NESegmentEntry) {
		let ne_header = self.ne.get_header();
		let offset = self.ne.get_header_offset() + ne_header.segment_table_offset as usize;

		let segment_table = &mut self.output[(offset + ((segment_number - 1) * 8) as usize) as usize..];
		LE::write_u16(segment_table, (data.offset / self.sector_alignment as u32) as u16);
		LE::write_u16(&mut segment_table[2..], data.data_size as u16);
		LE::write_u16(&mut segment_table[4..], data.flags.bits());
		LE::write_u16(&mut segment_table[6..], data.alloc_size as u16);

		println!("{} {:#?}", segment_number, &data);
	}

	pub fn unpack_normal_segment(&mut self, segment_number: u16) -> Result<usize, Box<std::error::Error>> {
		let offsets = OptOffsets {
			copy_from_offset: 0,
			copy_to_offset: 0,
			copy_length: 0,
			decompress_from_offset: 2,
			decompress_to_offset: 0
		};

		let segment_header = self.ne.get_segment_header(segment_number)?;
		let segment_data = self.ne.get_segment_data(segment_number)?;

		let num_relocations = LE::read_u16(segment_data);
		let output_segment_offset = self.output.len();

		let new_segment_header = {
			let mut header = segment_header.clone();
			header.offset = output_segment_offset as u32;
			header.data_size = header.alloc_size;

			if num_relocations > 0 {
				header.flags |= NESegmentFlags::HAS_RELOC;
			}

			header
		};

		// if segment_number == 2 {
		// 	self.debug = true;
		// 	println!("{:#?}", &new_segment_header);
		// 	println!("rel {}", num_relocations);
		// } else {
		// 	self.debug = false;
		// }

		self.set_segment_table_entry(segment_number, new_segment_header);

		let expected_size = self.output.len() + segment_header.alloc_size as usize;
		self.output.resize(expected_size, 0);
		let (relocations_offset, mut decompressed_size) = self.run_decompressor(&segment_data, output_segment_offset, offsets)?;

		// TODO: Verify that this is already the case (it should be!)
		// if decompressed_size < segment_header.alloc_size as usize {
		// 	for i in &mut self.output[output_segment_offset + decompressed_size..output_segment_offset + segment_header.alloc_size as usize] {
		// 		*i = 0;
		// 	}
		// }

		if num_relocations > 0 {
			self.output.extend_from_slice(&[ (num_relocations & 0xff) as u8, (num_relocations >> 8 & 0xff) as u8]);
			decompressed_size += 2;
			let converter = FixupConverter::new(&segment_data[relocations_offset..], num_relocations);
			for fixup in converter {
				self.output.extend_from_slice(&fixup);
				decompressed_size += fixup.len();
			}
		}

		decompressed_size += self.align_output();
		Ok(decompressed_size)
	}

	fn align_output(&mut self) -> usize {
		let last_sector_size = self.output.len() % self.sector_alignment;
		if last_sector_size != 0 {
			let padding_bytes = self.sector_alignment - last_sector_size;
			self.output.resize(self.output.len() + padding_bytes as usize, 0);
			padding_bytes
		} else {
			0
		}
	}
}

fn fix_file(in_filename: &str, out_filename: &str) -> Result<(usize, usize), Box<std::error::Error>> {
	let input = {
		let mut file = File::open(&in_filename)?;
		let mut input: Vec<u8> = Vec::with_capacity(file.metadata()?.len() as usize);
		file.read_to_end(&mut input)?;
		input
	};

	let executable = NEExecutable::new(&input)?;
	let mut unpacker = OptUnpacker::new(&executable)?;

	let name = match executable.get_name()? {
		Some(name) => name,
		None => in_filename.to_string()
	};

	println!("Unpacking {}", name);
	println!("{}", unpacker.get_copyright());

	let size = unpacker.unpack_boot_segment()?;
	println!("Unpacked boot segment ({} bytes)", size);

	for segment_number in 2..=executable.get_header().num_segments {
		let size = unpacker.unpack_normal_segment(segment_number)?;
		println!("Unpacked segment {} ({} bytes)", segment_number, size);
	}

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

	unpacker.write_to_file(out_filename)
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
