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
	fn get_bit(&mut self) -> Result<u8, Error> {
		let (instructions, bit) = self.instructions.overflowing_add(self.instructions);
		self.instructions = instructions;
		self.count -= 1;
		if self.count == 0 {
			self.fetch_instructions()?;
		}
		Ok(bit as u8)
	}

	#[inline]
	fn get_bits(&mut self, mut count: u8) -> Result<u8, Error> {
		let mut value: u8 = self.get_bit()?;
		count -= 1;
		while count != 0 {
			value = (value << 1) | self.get_bit()?;
			count -= 1;
		}
		Ok(value)
	}

	#[inline]
	fn get_byte(&mut self) -> Result<u8, Error> {
		if self.data.len() == 0 {
			return Err(Error::IncompleteData{ index: self.index });
		}
		let byte = self.data[0];
		self.data = &self.data[1..];
		self.index += 1;
		Ok(byte)
	}

	fn get_offset(&mut self) -> Result<u16, Error> {
		Ok(((match self.get_bits(2)? {
			0b00 => 0,
			0b01 => match self.get_bit()? {
				0 => 1,
				1 => 2 + self.get_bit()?,
				_ => unreachable!()
			},
			0b10 => match self.get_bit()? {
				0 => 4 + self.get_bits(2)?,
				1 => 8 + self.get_bits(3)?,
				_ => unreachable!()
			},
			0b11 => match self.get_bit()? {
				0 => 16 + self.get_bits(4)?,
				1 => match self.get_bit()? {
					0 => 32 + self.get_bits(4)?,
					1 => match self.get_bit()? {
						0 => 48 + self.get_bits(4)?,
						1 => 64 + self.get_bits(6)?,
						_ => unreachable!()
					},
					_ => unreachable!()
				},
				_ => unreachable!()
			},
			_ => unreachable!()
		} as u16) << 8) + self.get_byte()? as u16)
	}

	pub fn next_op(&mut self) -> Result<Op, Error> {
		Ok(match self.get_bit()? {
			0 => match self.get_bits(2)? {
				0b00 => Op::CopyBytes{ count: 2, offset: self.get_byte()? as u16 },
				0b01 => Op::CopyBytes{ count: 3, offset: self.get_offset()? },
				0b10 => Op::CopyBytes{ count: 4 + self.get_bit()?, offset: self.get_offset()? },
				0b11 => match self.get_bit()? {
					0 => Op::CopyBytes{ count: 6 + self.get_bit()?, offset: self.get_offset()? },
					1 => match self.get_bit()? {
						0 => Op::CopyBytes{ count: 8 + self.get_bits(2)?, offset: self.get_offset()? },
						1 => match self.get_bit()? {
							0 => Op::CopyBytes{ count: 12 + self.get_bits(3)?, offset: self.get_offset()? },
							1 => {
								let count = self.get_byte()?;
								if count < 0x81 {
									return Ok(Op::CopyBytes{ count: count, offset: self.get_offset()? });
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
			1 => Op::Literal(self.get_byte()?),
			_ => unreachable!()
		})
	}
}
