use procfs::process::{MemoryMap, Process};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::{env, fs::OpenOptions, os::unix::prelude::FileExt};

fn main() {
	//todo retry logic
	println!("----rchax by crazy good enterprises----");
	//x86_6 is not a typo
	let proc = procfs::process::all_processes()
		.unwrap()
		.into_iter()
		.filter(|x| x.stat.comm == "Robocraft.x86_6")
		.next()
		.unwrap();
	let pid = proc.pid;
	let mem_writer = OpenOptions::new()
		.read(true)
		.write(true)
		.open(format!("/proc/{pid}/mem"))
		.unwrap();
	let args: Vec<String> = env::args().collect();
	//godmode
	if let Some(x) = args.get(1) {
		match x.as_str() {
			"on" => {
				let (pos, _map) = scan(
					&proc,
					&hex::decode("41 89 47 5C 48 8B 1C 24 4C 8B 64 24 08 4C".replace(" ", ""))
						.unwrap(),
				)
				.unwrap();
				mem_writer
					.write_all_at(&hex::decode("90 90 90 90".replace(" ", "")).unwrap(), pos)
					.unwrap();
			}
			"off" => {
				let (pos, _map) = scan(
					&proc,
					&hex::decode("90 90 90 90 48 8B 1C 24 4C 8B 64 24 08 4C".replace(" ", ""))
						.unwrap(),
				)
				.unwrap();
				mem_writer
					.write_all_at(&hex::decode("41 89 47 5C".replace(" ", "")).unwrap(), pos)
					.unwrap();
			}
			_ => {
				panic!("undefined argument")
			}
		}
	}

	if let Some((pos, _map)) = scan(&proc, &hex::decode("F3 0F 10 00 F3 0F 5A C0 F2 0F 5A C0 EB 24 49 8B 46 18 49 63 CC 39 48 18 0F 86 85 00 00 00 48 8D 44 C8 20 4C 63 60 04 41 83 FC FF 74 1D E9 5F FF FF FF 4C 8B 24 24 4C 8B 6C 24 08 4C 8B 74 24 10 4C 8B 7C 24 18 48 83 C4 28 C3 BF CB 06 00 02 49".replace(" ", "")).unwrap())
	{
		mem_writer
		.write_all_at(&hex::decode("90 90 90 90".replace(" ", "")).unwrap(), pos)
		.unwrap();
	}

	if let Some((pos, _map)) = scan(&proc, &hex::decode("48 8B C7 F3 0F 10 40 48 F3 0F 5A C0 F2 0F 5A C0 48 83 C4 08 C3 00 00 00 48 83 EC 18 48 89 7C 24".replace(" ", "")).unwrap())
	{
		mem_writer
		.write_all_at(
			&hex::decode("F3 0F 10 05 F1 FF FF FF".replace(" ", "")).unwrap(),
			pos,
		)
		.unwrap();
	}

	println!("all done!");
}

fn scan(proc: &Process, pattern: &[u8]) -> Option<(u64, MemoryMap)> {
	let pid = proc.pid;
	let mem = OpenOptions::new()
		.read(true)
		.open(format!("/proc/{pid}/mem"))
		.unwrap();
	//todo thread local buffer
	return proc.maps().unwrap().into_par_iter().find_map_first(|map| {
		let (start, end) = map.address;
		let size = end - start;
		let mut buf = vec![0; size as usize];
		if let Ok(_) = mem.read_exact_at(buf.as_mut_slice(), start) {
			if let Some(x) = jetscii::ByteSubstring::new(pattern).find(&buf) {
				return Some((x as u64 + start, map));
			}
		}
		return None;
	});
}
