#![recursion_limit = "1024"]

mod decompressor;
mod fixup_converter;
mod neexe;
#[macro_use] mod util;

use byteorder::{ByteOrder, LittleEndian as LE};
use custom_error::custom_error;
use decompressor::{Decompressor, Error as DecompressorError, Op};
use fixup_converter::FixupConverter;
use neexe::*;
use nom::{do_parse, le_u16, named, named_args, tag, take_until, take_until_and_consume};
use std::io::prelude::*;
use std::io;
use std::fs::File;
use std::error::Error as StdError;

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

custom_error!{OptError
	NotSelfLoading     = "not a self-loading executable",
	MissingBootOffsets = "missing boot offsets",
	MissingCopyright   = "missing copyright string"
}

struct OptUnpacker<'a> {
	ne:                &'a NEExecutable<'a>,
	output:            Vec<u8>,
	copyright:         String,
	boot_code_offsets: OptOffsets,
	sector_alignment:  usize,
}

impl<'a> OptUnpacker<'a> {
	pub fn new(ne: &'a NEExecutable) -> Result<Self, Box<dyn StdError>> {
		let (header, boot_code_size) = match ne.get_selfload_header()? {
			Some((header, extra_header_data)) => (header, LE::read_u16(&extra_header_data[6..])),
			None => { return Err(Box::new(OptError::NotSelfLoading)); }
		};

		let (copyright, boot_code_offsets) = {
			let boot_code = &ne.get_segment_data(1)?[(header.boot_app_offset & 0xffff) as usize..];
			match detect_optloader(boot_code) {
				Ok((boot_init_code, copyright)) => {
					(copyright, match get_offsets(boot_init_code, boot_code_size) {
						Ok((_, offsets)) => offsets,
						Err(_) => { return Err(Box::new(OptError::MissingBootOffsets)); }
					})
				},
				Err(_) => { return Err(Box::new(OptError::MissingCopyright)); }
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

	pub fn unpack_all(&mut self) -> Result<(), Box<dyn StdError>> {
		// TODO: Delete the loader segment entirely instead? (It only needed
		// to be unpacked to reverse engineer the loader itself.)
		let size = self.unpack_boot_segment()?;
		println!("Unpacked boot segment ({} bytes)", size);

		for segment_number in 2..=self.ne.get_header().num_segments {
			let size = self.unpack_normal_segment(segment_number)?;
			println!("Unpacked segment {} ({} bytes)", segment_number, size);
		}

		let trailer_offset = match self.copy_resources() {
			Some(offset) => offset,
			None => {
				let last_segment = self.ne.get_segment_header(self.ne.get_header().num_segments)?;
				(last_segment.offset + last_segment.data_size) as usize
			}
		};

		let input = self.ne.get_raw_data();

		if trailer_offset != input.len() {
			let trailer_output_offset = self.output.len();
			self.output.extend_from_slice(&input[trailer_offset..]);
			println!("Copied trailer ({} bytes)", self.output.len() - trailer_output_offset);

			// HACK: This is Macromedia Director-specific
			let director_offset = LE::read_u32(&input[input.len() - 4..]) as usize;
			if director_offset >= trailer_offset && director_offset < input.len() {
				let output_director_offset = trailer_output_offset + director_offset - trailer_offset;

				let delta = output_director_offset - director_offset;

				let director_offset_offset = self.output.len() - 4;
				LE::write_u32(&mut self.output[director_offset_offset..], output_director_offset as u32);

				let mut director_data_table = &mut self.output[output_director_offset + 4..];
				for _ in 0..6 {
					let offset = LE::read_u32(director_data_table) as usize + delta;
					LE::write_u32(&mut director_data_table, offset as u32);
					director_data_table = &mut director_data_table[4..];
				}

				println!("Rewrote Director trailer");
			}
		}

		self.clear_selfload_header();
		println!("Removed self-loading header");

		Ok(())
	}

	pub fn unpack_boot_segment(&mut self) -> Result<usize, Box<dyn StdError>> {
		let segment_header = self.ne.get_segment_header(1)?;
		let segment_data = self.ne.get_segment_data(1)?;

		let input = {
			let mut input: Vec<u8> = Vec::with_capacity(segment_header.alloc_size as usize);
			input.extend_from_slice(segment_data);
			input.resize(segment_header.alloc_size as usize, 0);
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
		decompressed_size += self.align_output(self.sector_alignment);
		Ok(decompressed_size)
	}

	pub fn unpack_normal_segment(&mut self, segment_number: u16) -> Result<usize, Box<dyn StdError>> {
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

			total_size += self.align_output(self.sector_alignment);
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

	fn run_decompressor(&mut self, input: &[u8], input_offset: usize, output_offset: usize) -> Result<(usize, usize), DecompressorError> {
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

	fn write_to_file(&self, filename: &str) -> Result<(usize, usize), io::Error> {
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

	fn set_resource_offset(&mut self, mut resource_index: u16, alignment: usize, offset: usize) {
		let table_offset = self.ne.get_header_offset() + self.ne.get_header().resource_table_offset as usize;
		let mut resource_table = &mut self.output[table_offset + 2..];
		loop {
			let resources_in_block = LE::read_u16(&resource_table[2..]);
			if resource_index < resources_in_block {
				let resource = &mut resource_table[8 + resource_index as usize * 12..];
				assert_eq!(offset % alignment, 0);
				LE::write_u16(resource, (offset / alignment) as u16);
				break;
			} else {
				resource_index -= resources_in_block;
				resource_table = &mut resource_table[8 + resources_in_block as usize * 12..];
			}
		}
	}

	fn clear_selfload_header(&mut self) {
		let flags = self.ne.get_header().flags - NEFlags::SELF_LOAD;
		LE::write_u16(&mut self.output[self.ne.get_header_offset() + 12..], flags.bits());
	}

	fn copy_resources(&mut self) -> Option<usize> {
		if let Some(alignment_shift) = self.ne.get_resource_table_alignment_shift() {
			let alignment = 1 << alignment_shift;
			self.align_output(alignment);
			let input = self.ne.get_raw_data();

			let mut trailer_offset = 0;
			for (index, resource) in self.ne.iter_resources().enumerate() {
				let new_resource_start = self.output.len();
				let end_offset = resource.offset + resource.length;
				self.output.extend_from_slice(&input[resource.offset as usize..end_offset as usize]);
				self.align_output(alignment);
				self.set_resource_offset(index as u16, alignment, new_resource_start);
				if trailer_offset < end_offset {
					trailer_offset = end_offset;
				}
				println!("Copied resource {} ({} bytes)", index + 1, resource.length);
			}
			Some(trailer_offset as usize)
		} else {
			None
		}
	}

	fn align_output(&mut self, alignment: usize) -> usize {
		let last_sector_size = self.output.len() % alignment;
		if last_sector_size != 0 {
			let padding_bytes = alignment - last_sector_size;
			self.output.resize(self.output.len() + padding_bytes as usize, 0);
			padding_bytes
		} else {
			0
		}
	}
}

fn fix_file(in_filename: &str, out_filename: &str) -> Result<(usize, usize), Box<dyn StdError>> {
	let input = {
		let mut file = File::open(&in_filename)?;
		let mut input: Vec<u8> = Vec::with_capacity(file.metadata()?.len() as usize);
		file.read_to_end(&mut input)?;
		input
	};

	let executable = NEExecutable::new(&input)?;
	let mut unpacker = OptUnpacker::new(&executable)?;

	let name = match executable.get_name() {
		Some(name) => name,
		None => in_filename.to_string()
	};

	println!("Unpacking {}", name);
	println!("{}", unpacker.get_copyright());

	unpacker.unpack_all()?;

	Ok(unpacker.write_to_file(out_filename)?)
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
