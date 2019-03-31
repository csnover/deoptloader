use bitflags::bitflags;
use enum_primitive::*;
use nom::{apply, count, do_parse, le_u8, le_u16, le_u32, many_till, named, named_args, switch, tag, take, value};
use crate::util::read_pascal_string;

named!(pub get_ne_offset<u16>,
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
	pub entry_table_length:        u16,
	pub crc:                       u32,
	pub flags:                     NEFlags,
	pub auto_data_segment_index:   u16,
	pub heap_size:                 u16,
	pub stack_size:                u16,
	pub entry_point:               u32,
	pub init_stack_pointer:        u32,
	pub num_segments:              u16,
	pub num_imports:               u16,
	pub names_size:                u16,
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

named!(pub read_ne_header<NEHeader>,
	do_parse!(
/*0*/	                           tag!("NE") >>
/*2*/	linker_major_version:      le_u8 >>
/*3*/	linker_minor_version:      le_u8 >>
/*4*/	entry_table_offset:        le_u16 >> // relative to beginning of header
/*6*/	entry_table_length:        le_u16 >> // bytes
/*8*/	crc:                       le_u32 >>
/*12*/	flags:                     le_u16 >>
/*14*/	auto_data_segment_index:   le_u16 >>
/*16*/	heap_size:                 le_u16 >>
/*18*/	stack_size:                le_u16 >>
/*20*/	entry_point:               le_u32 >> // cs:ip
/*24*/	init_stack_pointer:        le_u32 >> // ss:sp
/*28*/	num_segments:              le_u16 >>
		num_imports:               le_u16 >>
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
			num_imports,
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
pub struct NESegmentEntry {
	pub offset:        u32, // bytes
	pub length:        u32, // bytes
	pub flags:         NESegmentFlags,
	pub alloc_size:    u32, // bytes
}

named_args!(pub get_segments(offset_shift: u16, num_segments: u16)<Vec<NESegmentEntry> >,
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
pub enum NEResourceKind {
	Predefined(NEPredefinedResourceKind),
	Integer(u16),
	String(String),
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

#[derive(Clone, Debug)]
pub struct NEResourceKindEntry {
	pub kind:      NEResourceKind,
	pub resources: Vec<NEResourceEntry>,
}

#[derive(Clone, Debug)]
pub struct NEResourceTable {
	pub alignment_shift_count: u16,
	pub resource_kinds: Vec<NEResourceKindEntry>,
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

named_args!(pub read_resource<'a>(resource_table: &'a [u8], offset_shift: u16)<NEResourceEntry>,
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

named_args!(pub read_resource_kind<'a>(resource_table: &'a [u8], offset_shift: u16)<NEResourceKindEntry>,
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

pub fn get_resource_table(input: &[u8]) -> nom::IResult<&[u8], NEResourceTable> {
	do_parse!(input,
		alignment_shift_count: le_u16 >>
		resource_kinds:        many_till!(apply!(read_resource_kind, input, alignment_shift_count), tag!("\0\0")) >>
		(NEResourceTable {
			alignment_shift_count,
			resource_kinds: resource_kinds.0
		})
	)
}

bitflags!(pub struct NEEntryPointFlags: u8 {
	const EXPORTED      = 1;
	const MULTIPLE_DATA = 2;
});

#[derive(Clone, Debug)]
pub enum NEEntryPoint {
	None,
	Movable{ flags: NEEntryPointFlags, dpmi_instruction: u16, segment: u8, offset: u16 },
	Constant{ flags: NEEntryPointFlags, segment: u8, offset: u16 },
}

named!(read_entry_point_bundle<Vec<NEEntryPoint> >,
	do_parse!(
		count: le_u8 >>
		entry_points: switch!(le_u8,
			0    => count!(value!(NEEntryPoint::None), count as usize) |
			0xff => count!(do_parse!(
				flags:             le_u8 >>
				dpmi_instruction:  le_u16 >>
				segment:           le_u8 >>
				offset:            le_u16 >>
				(NEEntryPoint::Movable {
					flags: NEEntryPointFlags::from_bits_truncate(flags),
					dpmi_instruction,
					segment,
					offset
				})
			), count as usize) |
			segment => count!(do_parse!(
				flags:  le_u8 >>
				offset: le_u16 >>
				(NEEntryPoint::Constant {
					flags: NEEntryPointFlags::from_bits_truncate(flags),
					segment,
					offset
				})
			), count as usize)
		) >> (entry_points)
	)
);

named!(pub get_entry_points<Vec<NEEntryPoint> >,
	do_parse!(
		results: many_till!(read_entry_point_bundle, tag!("\0")) >>
		(results.0.into_iter().flatten().collect())
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
pub enum NESegmentRelocationTarget {
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
pub struct NESegmentRelocation {
	pub kind:     NESegmentRelocationSourceKind,
	pub offset:   u16,
	pub additive: bool,
	pub target:   NESegmentRelocationTarget,
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

named!(pub read_relocations<Vec<NESegmentRelocation> >,
	do_parse!(
		length:      le_u16 >>
		relocations: count!(read_relocation, length as usize) >>
		(relocations)
	)
);

#[derive(Clone, Debug)]
pub struct NESelfLoadHeader {
	pub boot_app_offset:       u32,
	pub load_app_seg_offset:   u32,
}

named!(pub read_selfload_header<NESelfLoadHeader>,
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
		(NESelfLoadHeader {
			boot_app_offset,
			load_app_seg_offset
		})
	)
);
