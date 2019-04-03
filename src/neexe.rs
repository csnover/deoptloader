use bitflags::bitflags;
use byteorder::{ByteOrder, LE};
use custom_error::custom_error;
use crate::util::read_pascal_string;
use enum_primitive::*;
use nom::{apply, count, do_parse, le_u8, le_u16, le_u32, named, named_args, tag, take};

macro_rules! try_parse (
	($result: expr, $error: expr) => (match $result {
		Ok((_, result)) => result,
		Err(_) => { return Err($error); }
	})
);

custom_error!{pub ParseError
	NotMZ                                = "invalid MZ header",
	NotNE                                = "invalid NE header",
	SegmentHeader{ segment_number: u16 } = "invalid segment {segment_number} header",
	SelfLoadHeader                       = "invalid self-load header"
}

named!(get_ne_offset<u16>,
	do_parse!(
		           tag!("MZ") >>
		           take!(58) >>
		ne_offset: le_u16 >>
		(ne_offset)
	)
);

bitflags!(pub struct NEFlags: u16 {
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
pub struct NEHeader {
	pub linker_major_version:      u8,
	pub linker_minor_version:      u8,
	pub entry_table_offset:        u16,
	pub entry_table_size:          u16,
	pub crc:                       u32,
	pub flags:                     NEFlags,
	pub auto_data_segment_index:   u16,
	pub heap_size:                 u16,
	pub stack_size:                u16,
	pub entry_point:               u32,
	pub init_stack_pointer:        u32,
	pub num_segments:              u16,
	pub num_imports:               u16,
	pub non_resident_table_size:   u16,
	pub segment_table_offset:      u16, // bytes, from start of NEHeader
	pub resource_table_offset:     u16,
	pub names_table_offset:        u16,
	pub module_table_offset:       u16,
	pub import_names_table_offset: u16,
	pub non_resident_table_offset: u32,
	pub num_movable_entry_point:   u16,
	pub alignment_shift_count:     u16, // 1 << alignment_shift_count = logical sector
	pub num_resources:             u16,
	pub target_os:                 u8,
	pub os2_flags:                 u8,
	pub thunk_offset:              u16,
	pub segment_thunk_offset:      u16,
	pub min_code_swap_size:        u16,
	pub win_version_minor:         u8,
	pub win_version_major:         u8,
}

bitflags!(pub struct NESegmentFlags: u16 {
	const CODE      = 0x0000;
	const DATA      = 0x0001;
	const MOVABLE   = 0x0010;
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
		entry_table_size:          le_u16 >> // bytes
		crc:                       le_u32 >>
		flags:                     le_u16 >>
		auto_data_segment_index:   le_u16 >>
		heap_size:                 le_u16 >>
		stack_size:                le_u16 >>
		entry_point:               le_u32 >> // cs:ip
		init_stack_pointer:        le_u32 >> // ss:sp
		num_segments:              le_u16 >>
		num_imports:               le_u16 >>
		non_resident_table_size:   le_u16 >>
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
			entry_table_size,
			crc,
			flags: NEFlags::from_bits_truncate(flags),
			auto_data_segment_index,
			heap_size,
			stack_size,
			entry_point,
			init_stack_pointer,
			num_segments,
			num_imports,
			non_resident_table_size,
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
pub struct NESegmentEntry {
	pub offset:     u32, // bytes
	pub data_size:  u32, // bytes
	pub flags:      NESegmentFlags,
	pub alloc_size: u32, // bytes
}

named_args!(read_segment_header(offset_shift: u16)<NESegmentEntry>,
	do_parse!(
		offset:     le_u16 >>
		data_size:  le_u16 >>
		flags:      le_u16 >>
		alloc_size: le_u16 >>
		(NESegmentEntry {
			offset:     (offset as u32) << offset_shift,
			data_size:  if data_size == 0 { 0x10000 } else { data_size.into() },
			flags:      NESegmentFlags::from_bits_truncate(flags),
			alloc_size: if alloc_size == 0 { 0x10000 } else { alloc_size.into() }
		})
	)
);

named_args!(get_segments(offset_shift: u16, num_segments: u16)<Vec<NESegmentEntry> >,
	count!(apply!(read_segment_header, offset_shift), num_segments as usize)
);

bitflags!(pub struct NEResourceFlags: u16 {
	const MOVABLE = 0x10;
	const PURE    = 0x20;
	const PRELOAD = 0x40;
});

enum_from_primitive! {
	#[derive(Clone, Debug)]
	pub enum NEPredefinedResourceKind {
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
pub enum NEResourceId {
	Integer(u16),
	String(String),
}

#[derive(Clone, Debug)]
pub struct NEResourceEntry {
	pub offset: u32, // bytes
	pub length: u32, // bytes
	pub flags:  NEResourceFlags,
	pub id:     NEResourceId,
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

enum_from_primitive! {
	#[derive(Clone, Debug)]
	pub enum NESegmentRelocationSourceKind {
		LoByte  = 0,
		Segment = 2,
		FarAddr = 3,
		Offset  = 5,
	}
}

#[derive(Clone, Debug)]
pub struct NESelfLoadHeader {
	pub boot_app_offset:     u32,
	pub load_app_seg_offset: u32,
}

named!(read_selfload_header<NESelfLoadHeader>,
	do_parse!(
		                       tag!("A0") >>
		                       take!(2) >>     // reserved
		boot_app_offset:       le_u32 >>       // segment:offset
		load_app_seg_offset:   le_u32 >>       // segment:offset
		                       take!(4) >>     // reserved
		                       take!(4) >>     // mem alloc
		                       take!(4) >>     // ordinal resolve
		                       take!(4) >>     // exit
		                       take!(2 * 4) >> // reserved
		                       take!(4) >>     // set owner
		(NESelfLoadHeader {
			boot_app_offset,
			load_app_seg_offset
		})
	)
);

const SEGMENT_HEADER_SIZE: u16 = 8;
const FIXUP_SIZE: u16 = 8;

pub struct NEExecutable<'a> {
	input:         &'a [u8],
	header:        NEHeader,
	header_offset: u16,
	// A raw header slice is stored to make it easier to resolve offsets which
	// are relative to the start of the NE header
	raw_header:    &'a [u8],
}

pub struct NEResourcesIterator<'a> {
	table:        &'a [u8],
	index:        usize,
	offset_shift: u16,
	block_index:  u16,
	block_len:    u16,
	finished:     bool,
}

impl<'a> NEResourcesIterator<'a> {
	pub fn new(table: &'a [u8]) -> NEResourcesIterator<'a> {
		let offset_shift = LE::read_u16(table);
		let mut iterator = NEResourcesIterator {
			table,
			index: 2,
			offset_shift,
			block_index: 0,
			block_len: 0,
			finished: false,
		};
		iterator.load_next_block();
		iterator
	}

	fn load_next_block(&mut self) {
		self.finished = LE::read_u16(&self.table[self.index..]) == 0;
		if !self.finished {
			self.block_index = 0;
			self.block_len = LE::read_u16(&self.table[self.index + 2..]);
			self.index += 8;
		}
	}
}

impl<'a> Iterator for NEResourcesIterator<'a> {
	type Item = NEResourceEntry;

	fn next(&mut self) -> Option<Self::Item> {
		if self.block_index == self.block_len {
			self.load_next_block();
		}

		if self.finished {
			None
		} else {
			let (_, header) = read_resource(&self.table[self.index..], self.table, self.offset_shift).unwrap();
			self.index += 12;
			self.block_index += 1;
			Some(header)
		}
	}
}

impl<'a> NEExecutable<'a> {
	pub fn new(input: &'a [u8]) -> Result<Self, ParseError> {
		let header_offset = try_parse!(get_ne_offset(input), ParseError::NotMZ);
		let raw_header = &input[header_offset as usize..];
		let header = try_parse!(read_ne_header(raw_header), ParseError::NotNE);

		Ok(NEExecutable {
			input,
			header,
			header_offset, // TODO: Get rid of this
			raw_header
		})
	}

	pub fn get_raw_data(&self) -> &'a [u8] {
		self.input
	}

	pub fn get_header_offset(&self) -> usize {
		self.header_offset as usize
	}

	pub fn get_name(&self) -> Option<String> {
		if self.header.non_resident_table_size == 0 {
			None
		} else {
			let ne_non_resident_table = &self.input[self.header.non_resident_table_offset as usize..];
			match read_pascal_string(&ne_non_resident_table) {
				Ok((_, name)) => Some(name),
				Err(_) => None
			}
		}
	}

	pub fn get_header(&self) -> &NEHeader {
		&self.header
	}

	pub fn get_selfload_header(&self) -> Result<Option<(NESelfLoadHeader, &[u8])>, ParseError> {
		if self.header.flags.contains(NEFlags::SELF_LOAD) {
			Ok(Some(self.get_selfload_header_impl()?))
		} else {
			Ok(None)
		}
	}

	/// # Arguments
	/// * segment_number - 1-indexed segment number
	pub fn get_segment_header(&self, segment_number: u16) -> Result<NESegmentEntry, ParseError> {
		assert!(segment_number != 0 || segment_number <= self.header.num_segments, format!("segment number {} is out of range", segment_number));
		let offset = self.header.segment_table_offset + ((segment_number - 1) * SEGMENT_HEADER_SIZE);
		match read_segment_header(&self.raw_header[offset as usize..], self.header.alignment_shift_count) {
			Ok((_, header)) => Ok(header),
			Err(_) => Err(ParseError::SegmentHeader{ segment_number })
		}
	}

	/// # Arguments
	/// * segment_number - 1-indexed segment number
	pub fn get_segment_data(&self, segment_number: u16) -> Result<&[u8], ParseError> {
		let header = self.get_segment_header(segment_number)?;
		let data = &self.input[header.offset as usize..];
		let mut size = header.data_size as usize;
		if header.flags.contains(NESegmentFlags::HAS_RELOC) {
			let fixup_table_size = LE::read_u16(&data[size..]) as usize * FIXUP_SIZE as usize;
			size += fixup_table_size;
		}
		Ok(&data[..size])
	}

	pub fn get_resource_table_alignment_shift(&self) -> Option<u16> {
		if let Some(table) = self.get_resource_table_data() {
			Some(LE::read_u16(table))
		} else {
			None
		}
	}

	pub fn get_resource_table_data(&self) -> Option<&[u8]> {
		if self.header.resource_table_offset == 0 {
			None
		} else {
			Some(&self.raw_header[self.header.resource_table_offset as usize..])
		}
	}

	pub fn iter_resources(&self) -> NEResourcesIterator {
		NEResourcesIterator::new(&self.raw_header[self.header.resource_table_offset as usize..])
	}

	fn get_selfload_header_impl(&self) -> Result<(NESelfLoadHeader, &[u8]), ParseError> {
		let segment_data = self.get_segment_data(1)?;
		match read_selfload_header(segment_data) {
			Ok(header) => Ok((header.1, header.0)),
			Err(_) => Err(ParseError::SelfLoadHeader)
		}
	}
}
