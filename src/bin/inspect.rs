use deoptloader::*;
use std::io::Read;

fn main() {
	let args: Vec<_> = std::env::args().collect();
	if args.len() < 2 {
		println!("Usage: {} <NE executable>", &args[0]);
		std::process::exit(1);
	}

	let data = {
		let mut file = std::fs::File::open(&args[1]).unwrap();
		let mut data = Vec::new();
		file.read_to_end(&mut data).unwrap();
		data
	};

	let exe = neexe::NEExecutable::new(&data).unwrap();
	if let Some(name) = exe.name() {
		println!("{}", name);
	}
	if let Ok(Some(_)) = exe.selfload_header() {
		println!("Self-loading");
	}
	if exe.has_resource_table() {
		println!("Resources:");
		for resource in exe.iter_resources() {
			println!("{:?}", resource);
			if resource.kind == neexe::NEResourceKind::Predefined(neexe::NEPredefinedResourceKind::StringTable) {
				println!("  Strings in table:");
				let mut string_table = &exe.raw_data()[resource.offset as usize..(resource.offset + resource.length) as usize];
				match resource.id {
					neexe::NEResourceId::Integer(base_id) => {
						let base_id = u32::from(base_id - 1) << 4;
						for i in 0..16 {
							let result = util::read_pascal_string(&string_table).unwrap();
							string_table = result.0;
							let value = result.1;
							if !value.is_empty() {
								println!("  {:5}: {}", base_id + i, value.replace('\r', "^r").replace('\n', "^n"));
							}
						}
					},
					_ => panic!()
				};
			}
		}
	}
}
