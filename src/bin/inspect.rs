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

	let exe = deoptloader::neexe::NEExecutable::new(&data).unwrap();
	if let Some(name) = exe.name() {
		println!("{}", name);
	}
	if let Ok(Some(_)) = exe.selfload_header() {
		println!("Self-loading");
	}
	println!("Resources:");
	for resource in exe.iter_resources() {
		println!("{:?}", resource);
	}
}
