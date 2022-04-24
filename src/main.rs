#![feature(thread_local, default_free_fn)]

use hex_literal::hex;
use procfs::process::{MemoryMap, Process};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::{
	collections::HashMap,
	default::default,
	env,
	fs::{File, OpenOptions},
	os::unix::prelude::FileExt,
};

fn main() {
	println!("----rchax by crazy good enterprises----");
	let args: Vec<String> = env::args().collect();
	let mut state = State::new();
	loop {
		//godmode
		if let Some(x) = args.get(1) {
			match x.as_str() {
				"on" => {
					state.replace(
						&hex!("41 89 47 5C 48 8B 1C 24 4C 8B 64 24 08 4C"),
						&hex!("90 90 90 90"),
					);
				}
				"off" => {
					state.replace(
						&hex!("90 90 90 90 48 8B 1C 24 4C 8B 64 24 08 4C"),
						&hex!("41 89 47 5C"),
					);
				}
				_ => {
					panic!("undefined argument")
				}
			}
		}

		state.replace(&hex!("F3 0F 10 00 F3 0F 5A C0 F2 0F 5A C0 EB 24 49 8B 46 18 49 63 CC 39 48 18 0F 86 85 00 00 00 48 8D 44 C8 20 4C 63 60 04 41 83 FC FF 74 1D E9 5F FF FF FF 4C 8B 24 24 4C 8B 6C 24 08 4C 8B 74 24 10 4C 8B 7C 24 18 48 83 C4 28 C3 BF CB 06 00 02 49"),
		&hex!("90 90 90 90"));

		state.replace(&hex!("48 8B C7 F3 0F 10 40 48 F3 0F 5A C0 F2 0F 5A C0 48 83 C4 08 C3 00 00 00 48 83 EC 18 48 89 7C 24"),
		&hex!("F3 0F 10 05 F1 FF FF FF"));

		if !state.retry {
			break;
		}
	}

	println!("all done!");
}

struct State {
	proc: Process,
	mem: File,
	dry: HashMap<&'static [u8], ()>,
	retry: bool,
}

impl State {
	fn new() -> Self {
		//x86_6 is not a typo
		let proc = procfs::process::all_processes()
			.unwrap()
			.into_iter()
			.filter(|x| x.stat.comm == "Robocraft.x86_6")
			.next()
			.unwrap();
		let pid = proc.pid;
		let mem = OpenOptions::new()
			.read(true)
			.write(true)
			.open(format!("/proc/{pid}/mem"))
			.unwrap();
		Self {
			proc: proc,
			mem: mem,
			retry: false,
			dry: default(),
		}
	}
	fn replace(&mut self, org: &'static [u8], patch: &[u8]) {
		if self.dry.contains_key(org) {
			return;
		}
		if let Some((pos, _map)) = scan(&self.proc, org) {
			self.mem.write_all_at(patch, pos).unwrap();
			assert!(self.dry.insert(org, ()).is_none());
			return;
		}
		self.retry = true;
	}
}

#[thread_local]
static mut TLS_BUF: Vec<u8> = Vec::new();

fn scan(proc: &Process, pattern: &[u8]) -> Option<(u64, MemoryMap)> {
	let pid = proc.pid;
	let mem = OpenOptions::new()
		.read(true)
		.open(format!("/proc/{pid}/mem"))
		.unwrap();
	return proc.maps().unwrap().into_par_iter().find_map_first(|map| {
		let (start, end) = map.address;
		let size = (end - start).try_into().unwrap();
		unsafe {
			if !(size > TLS_BUF.len()) {
				TLS_BUF.truncate(size);
			} else {
				TLS_BUF.reserve(size - TLS_BUF.len())
			}
			TLS_BUF.set_len(size);
		}
		if let Ok(_) = mem.read_exact_at(unsafe { TLS_BUF.as_mut_slice() }, start) {
			if let Some(x) = jetscii::ByteSubstring::new(pattern).find(unsafe { &TLS_BUF }) {
				return Some((x as u64 + start, map));
			}
		}
		return None;
	});
}
