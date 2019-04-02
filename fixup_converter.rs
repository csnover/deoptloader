use byteorder::{ByteOrder, LE};
use crate::err;
use crate::neexe::NESegmentRelocationSourceKind as SourceKind;
use enum_primitive::FromPrimitive;
use std::io::Error;

#[derive(Debug)]
enum GroupKind {
	ZeroOffsetInternalRef,
	InternalRef { flags: u8, segment: u8, },
	Import      { flags: u8, index:   u16, },
	OsFixup     { flags: u8, kind:    u16, },
}

pub struct FixupConverter<'a> {
	input:             &'a [u8],
	total_count:       u16,
	group_count:       u8,
	group_source_kind: SourceKind,
	group_kind:        GroupKind,
}

impl<'a> FixupConverter<'a> {
	pub fn new(input: &'a [u8], total_count: u16) -> FixupConverter {
		FixupConverter {
			input,
			total_count,
			group_count:       0,
			group_source_kind: SourceKind::LoByte,
			group_kind:        GroupKind::ZeroOffsetInternalRef
		}
	}

	fn next_group(&mut self) -> Result<(), Error> {
		let operation = self.input[0];
		self.group_count = self.input[1];

		if self.group_count as u16 > self.total_count {
			err!("More relocations in relocation record group than total number of relocations");
		}

		self.total_count -= self.group_count as u16;

		if operation == 0xf0 {
			self.group_kind = GroupKind::ZeroOffsetInternalRef;
			self.group_source_kind = SourceKind::Offset;
			self.input = &self.input[2..];
		} else {
			self.group_source_kind = match operation & 3 {
				0 => SourceKind::LoByte,
				1 => SourceKind::Segment,
				2 => SourceKind::FarAddr,
				3 => SourceKind::Offset,
				_ => unreachable!()
			};
			let additive = operation & 4;
			match (operation >> 3) & 3 {
				0 => {
					self.group_kind = GroupKind::InternalRef {
						flags:   additive,
						segment: self.input[2]
					};
					self.input = &self.input[3..];
				},
				kind @ 1...2 => {
					self.group_kind = GroupKind::Import {
						flags: kind + additive,
						index: LE::read_u16(&self.input[2..])
					};
					self.input = &self.input[4..];
				},
				3 => {
					self.group_kind = GroupKind::OsFixup {
						flags: 3 + additive,
						kind:  match LE::read_u16(&self.input[2..]) {
							kind @ 1...6 => kind,
							kind => panic!("Invalid OsFixup type {}", kind)
						}
					};
					self.input = &self.input[4..];
				},
				_ => unreachable!()
			};
		}

		Ok(())
	}
}

const FIXUP_RECORD_SIZE: usize = 8;
impl<'a> Iterator for FixupConverter<'a> {
	type Item = [u8; FIXUP_RECORD_SIZE];

	fn next(&mut self) -> Option<Self::Item> {
		if self.group_count == 0 && (self.total_count == 0 || !self.next_group().is_ok()) {
			return None;
		}

		self.group_count -= 1;

		let mut record: [u8; FIXUP_RECORD_SIZE] = [0; FIXUP_RECORD_SIZE];
		record[0] = self.group_source_kind.clone() as u8;

		match self.group_kind {
			GroupKind::ZeroOffsetInternalRef => {
				record[2] = self.input[1];
				record[3] = self.input[2];
				record[4] = self.input[0];
				self.input = &self.input[3..];
			},
			GroupKind::InternalRef { flags, segment } => {
				record[1] = flags;
				record[2] = self.input[0];
				record[3] = self.input[1];
				record[4] = segment;
				record[6] = self.input[2];
				record[7] = self.input[3];
				self.input = &self.input[4..];
			},
			GroupKind::Import { flags, index } => {
				record[1] = flags;
				record[2] = self.input[0];
				record[3] = self.input[1];
				LE::write_u16(&mut record[4..], index);
				record[6] = self.input[2];
				record[7] = self.input[3];
				self.input = &self.input[4..];
			},
			GroupKind::OsFixup { flags, kind } => {
				record[1] = flags;
				record[2] = self.input[0];
				record[3] = self.input[1];
				LE::write_u16(&mut record[4..], kind);
				self.input = &self.input[2..];
			}
		}

		Some(record)
	}
}
