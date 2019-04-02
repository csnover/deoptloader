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
	copyright:         String,
	boot_code_offsets: OptOffsets,
	sector_alignment:  usize,
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

		Ok(OptUnpacker {
			ne,
			output,
			copyright,
			boot_code_offsets,
			sector_alignment: 1 << ne.get_header().alignment_shift_count,
		})
	}

	pub fn get_copyright(&self) -> &String {
		&self.copyright
	}

	pub fn unpack_boot_segment(&mut self) -> Result<usize, Box<std::error::Error>> {
		let segment_header = self.ne.get_segment_header(1)?;
		let segment_data = self.ne.get_segment_data(1)?;

		// TODO: Eliminate this extra copy?
		let input = {
			let mut input: Vec<u8> = Vec::with_capacity(segment_header.alloc_size as usize);
			input.extend_from_slice(segment_data);
			input.resize(segment_header.alloc_size as usize, 0);
			// TODO: Why is the last byte not being copied without the +1?
			safemem::copy_over(
				&mut input,
				self.boot_code_offsets.copy_from_offset as usize,
				self.boot_code_offsets.copy_to_offset as usize,
				self.boot_code_offsets.copy_length as usize + 1
			);
			input
		};

		let (input_offset, output_offset) = (self.boot_code_offsets.decompress_from_offset as usize, self.boot_code_offsets.decompress_to_offset as usize);

		let output_segment_offset = self.output.len();
		let max_needed_size = output_segment_offset + segment_header.alloc_size as usize;
		self.output.extend_from_slice(&input);
		self.output.resize(max_needed_size, 0);

		let (_, mut decompressed_size) = self.run_decompressor(&input, input_offset, output_segment_offset + output_offset)?;
		decompressed_size += output_offset;
		self.output.resize(output_segment_offset + decompressed_size as usize, 0);

		let new_segment_header = {
			let mut header = segment_header.clone();
			header.data_size = decompressed_size as u32;
			header
		};
		self.set_segment_table_entry(1, new_segment_header);

		if segment_header.flags.contains(NESegmentFlags::HAS_RELOC) {
			let fixup_table = &segment_data[segment_header.data_size as usize..];
			self.output.extend_from_slice(fixup_table);
			decompressed_size += fixup_table.len();
		}
		decompressed_size += self.align_output();
		Ok(decompressed_size)
	}

	pub fn unpack_normal_segment(&mut self, segment_number: u16) -> Result<usize, Box<std::error::Error>> {
		let segment_header = self.ne.get_segment_header(segment_number)?;
		let segment_data = self.ne.get_segment_data(segment_number)?;

		let output_segment_offset = self.output.len();

		let (has_relocations, code_size, total_size) = if segment_header.data_size > 0 {
			let num_relocations = LE::read_u16(segment_data);
			let extra_data = segment_header.offset % 512;
			let aligned_offset = (segment_header.offset - extra_data) as usize;
			let aligned_input = &self.ne.get_raw_data()[aligned_offset..aligned_offset + segment_data.len() + extra_data as usize];

			let max_needed_size = output_segment_offset + segment_header.alloc_size as usize;
			self.output.extend_from_slice(aligned_input);
			if max_needed_size > self.output.len() {
				self.output.resize(max_needed_size, 0);
			}

			let (relocations_offset, decompressed_size) = self.run_decompressor(segment_data, 2, output_segment_offset)?;
			self.output.resize(output_segment_offset + decompressed_size as usize, 0);

			let mut total_size = decompressed_size;
			if num_relocations > 0 {
				self.output.extend_from_slice(&[ (num_relocations & 0xff) as u8, (num_relocations >> 8 & 0xff) as u8 ]);
				total_size += 2;
				let converter = FixupConverter::new(&segment_data[relocations_offset..], num_relocations);
				for fixup in converter {
					self.output.extend_from_slice(&fixup);
					total_size += fixup.len();
				}
			}

			total_size += self.align_output();
			(num_relocations > 0, decompressed_size, total_size)
		} else {
			(false, 0, 0)
		};

		let new_segment_header = {
			let mut header = segment_header.clone();
			header.offset = output_segment_offset as u32;
			header.data_size = code_size as u32;
			if has_relocations {
				header.flags |= NESegmentFlags::HAS_RELOC;
			}
			header
		};
		self.set_segment_table_entry(segment_number, new_segment_header);
		Ok(total_size)
	}

	fn run_decompressor(&mut self, input: &[u8], input_offset: usize, output_offset: usize) -> Result<(usize, usize), Error> {
		let mut decompressor = Decompressor::new(&input[input_offset..])?;
		let mut output_index = output_offset;

		loop {
			let op = decompressor.next_op()?;
			match op {
				Op::Noop => {
					continue;
				},
				Op::Literal(value) => {
					self.output[output_index] = value;
					output_index += 1;
				},
				Op::Terminate(input_index) => {
					return Ok((input_offset + input_index, output_index - output_offset));
				},
				Op::CopyBytes{ offset, count } => {
					for i in 0..count {
						self.output[output_index + i as usize] = self.output[output_index - (offset as usize) - 1 + i as usize];
					}
					output_index += count as usize;
				}
			}
		}
	}

	fn write_to_file(&self, filename: &str) -> Result<(usize, usize), Box<std::error::Error>> {
		std::fs::write(filename, &self.output)?;
		Ok((self.ne.get_raw_data().len(), self.output.len()))
	}

	fn set_segment_table_entry(&mut self, segment_number: u16, data: NESegmentEntry) {
		let ne_header = self.ne.get_header();
		let offset = self.ne.get_header_offset() + ne_header.segment_table_offset as usize;

		let segment_table = &mut self.output[(offset + ((segment_number - 1) * 8) as usize) as usize..];
		assert_eq!((data.offset % self.sector_alignment as u32), 0);
		LE::write_u16(segment_table, (data.offset / self.sector_alignment as u32) as u16);
		LE::write_u16(&mut segment_table[2..], data.data_size as u16);
		LE::write_u16(&mut segment_table[4..], data.flags.bits());
		LE::write_u16(&mut segment_table[6..], data.alloc_size as u16);
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
	// - Rewrite resource table and copy resources
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
			println!("Successfully unpacked {} to {} ({} -> {} bytes)", in_filename, out_filename, in_size, out_size);
		},
		Err(e) => {
			println!("Failed to unpack {}: {}", in_filename, e);
			std::process::exit(1);
		}
	};
}
