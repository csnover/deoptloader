use byteorder::{ByteOrder, LittleEndian as LE};
use custom_error::custom_error;

custom_error!{pub Error
	IncompleteCode{index: usize} = "premature end of code stream at {index}",
	IncompleteData{index: usize} = "premature end of data stream at {index}"
}

#[derive(Debug)]
pub enum Op {
	Literal(u8),
	CopyBytes { count: u8, offset: u16 },
	Terminate(usize),
	Noop
}

#[derive(Debug)]
pub struct Decompressor<'data> {
	data:         &'data[u8],
	index:        usize,
	instructions: u16,
	count:        u8,
}

impl<'data> Decompressor<'data> {
	pub fn new(data: &'data [u8]) -> Result<Decompressor, Error> {
		let mut decompressor = Decompressor {
			data,
			index: 0,
			instructions: 0,
			count: 0,
		};
		decompressor.fetch_instructions()?;
		Ok(decompressor)
	}

	#[inline]
	fn fetch_instructions(&mut self) -> Result<(), Error> {
		if self.data.len() < 2 {
			return Err(Error::IncompleteCode{ index: self.index });
		}

		self.instructions = LE::read_u16(&self.data);
		self.data = &self.data[2..];
		self.index += 2;
		self.count = 16;
		Ok(())
	}

	#[inline]
	fn read_bit(&mut self) -> Result<u8, Error> {
		let (instructions, bit) = self.instructions.overflowing_add(self.instructions);
		self.instructions = instructions;
		self.count -= 1;
		if self.count == 0 {
			self.fetch_instructions()?;
		}
		Ok(bit as u8)
	}

	#[inline]
	fn read_bits(&mut self, mut count: u8) -> Result<u8, Error> {
		let mut value: u8 = self.read_bit()?;
		count -= 1;
		while count != 0 {
			value = (value << 1) | self.read_bit()?;
			count -= 1;
		}
		Ok(value)
	}

	#[inline]
	fn read_byte(&mut self) -> Result<u8, Error> {
		if self.data.is_empty() {
			return Err(Error::IncompleteData{ index: self.index });
		}
		let byte = self.data[0];
		self.data = &self.data[1..];
		self.index += 1;
		Ok(byte)
	}

	fn read_offset(&mut self) -> Result<u16, Error> {
		Ok((u16::from(match self.read_bits(2)? {
			0b00 => 0,
			0b01 => match self.read_bit()? {
				0 => 1,
				1 => 2 + self.read_bit()?,
				_ => unreachable!()
			},
			0b10 => match self.read_bit()? {
				0 => 4 + self.read_bits(2)?,
				1 => 8 + self.read_bits(3)?,
				_ => unreachable!()
			},
			0b11 => match self.read_bit()? {
				0 => 16 + self.read_bits(4)?,
				1 => match self.read_bit()? {
					0 => 32 + self.read_bits(4)?,
					1 => match self.read_bit()? {
						0 => 48 + self.read_bits(4)?,
						1 => 64 + self.read_bits(6)?,
						_ => unreachable!()
					},
					_ => unreachable!()
				},
				_ => unreachable!()
			},
			_ => unreachable!()
		}) << 8) + u16::from(self.read_byte()?))
	}

	pub fn next_op(&mut self) -> Result<Op, Error> {
		Ok(match self.read_bit()? {
			0 => match self.read_bits(2)? {
				0b00 => Op::CopyBytes{ count: 2, offset: u16::from(self.read_byte()?) },
				0b01 => Op::CopyBytes{ count: 3, offset: self.read_offset()? },
				0b10 => Op::CopyBytes{ count: 4 + self.read_bit()?, offset: self.read_offset()? },
				0b11 => match self.read_bit()? {
					0 => Op::CopyBytes{ count: 6 + self.read_bit()?, offset: self.read_offset()? },
					1 => match self.read_bit()? {
						0 => Op::CopyBytes{ count: 8 + self.read_bits(2)?, offset: self.read_offset()? },
						1 => match self.read_bit()? {
							0 => Op::CopyBytes{ count: 12 + self.read_bits(3)?, offset: self.read_offset()? },
							1 => {
								let count = self.read_byte()?;
								if count < 0x81 {
									return Ok(Op::CopyBytes{ count, offset: self.read_offset()? });
								} else if count != 0x81 {
									return Ok(Op::Terminate(self.index));
								} else {
									return Ok(Op::Noop);
								}
							},
							_ => unreachable!()
						},
						_ => unreachable!()
					},
					_ => unreachable!()
				},
				_ => unreachable!()
			},
			1 => Op::Literal(self.read_byte()?),
			_ => unreachable!()
		})
	}
}
