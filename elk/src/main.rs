use std::{
    env,
    error::Error,
    fs,
    io::{stdin, Write},
    process::{self, Command, Stdio},
    slice::from_raw_parts_mut,
};

use delf::{types::*, File};
use mmap::{MapOption, MemoryMap};
use region::{protect, Protection};

pub mod tables;

use tables::*;

fn main() -> Result<(), Box<dyn Error>> {
    let path = env::args().nth(1).expect("Usage: elk <file_path>");
    let input = fs::read(&path)?;
    if let Some(ref file) = File::parse_or_print_error(&input[..]) {
        if let Some(ds) = file
            .program_headers
            .iter()
            .find(|h| h.typ == delf::types::SegmentType::Dynamic)
        {
            if let delf::types::SegmentContent::Dynamic(ref table) = ds.contents {
                for entry in table {
                    println!("entry: {:?}", entry);
                }
            }
        }
        let base = 0x400000usize;
        let file_table = Table::from(file).build();
        let prog_table = Table::from(&file.program_headers).build();
        println!("{}{}", file_table, prog_table);
        println!("Disassembling {}...", &path);
        let prog_header = file
            .program_headers
            .iter()
            .find(|ph| ph.mem_range().contains(&file.entry_point))
            .expect("entry point not found in program headers");
        let code = &prog_header.data;
        ndisasm(code, file.entry_point)?;
        println!("Mapping segments...");
        let mut mappings = Vec::new();
        for ph in file
            .program_headers
            .iter()
            .filter(|h| h.typ == SegmentType::Load)
            .filter(|h| h.mem_size.0 as usize > 0)
        {
            let start = ph.virt_addr.0 as usize + base;
            let aligned = align_down(start, 0x1000);
            let padding = start - aligned;
            let memory_range = aligned..(aligned + ph.mem_size.0 as usize + padding);
            println!("Mapping segment at {:?} with {:?}", memory_range, ph.flags);
            let addr: *mut u8 = aligned as _;
            println!("Address: {:p}", addr);
            let map = MemoryMap::new(
                ph.mem_size.0 as usize + padding,
                &[MapOption::MapWritable, MapOption::MapAddr(addr)],
            )?;

            println!("Copy segment data to memory region...");
            {
                let dst = unsafe { from_raw_parts_mut(addr.add(padding), ph.data.len()) };
                dst.copy_from_slice(&ph.data[..]);
            }

            println!("setting permissions...");

            let protection = ph.flags.iter().fold(Protection::NONE, |acc, f| {
                acc | match f {
                    SegmentFlags::Read => Protection::READ,
                    SegmentFlags::Write => Protection::WRITE,
                    SegmentFlags::Execute => Protection::EXECUTE,
                }
            });
            unsafe {
                protect(addr, ph.data.len() + padding, protection)?;
            }
            println!("Done. Saving map");
            mappings.push(map);
        }

        let code_ptr = code.as_ptr();

        pause("make code executable")?;

        unsafe {
            protect(code_ptr, code.len(), Protection::READ_WRITE_EXECUTE)?;
        }

        println!("jump to {:?}", file.entry_point);
        // println!("entry offset @ {:?}", entry_offset);
        // println!(" entry point @ {:?}", entry_point);

        pause("jump")?;

        unsafe { jmp((file.entry_point.0 as usize + base) as _) };
    } else {
        process::exit(1);
    }

    Ok(())
}

fn align_up(addr: usize, align: usize) -> usize {
    println!("aligning {:#x} to {:#x}", addr, align);
    let aligned = (addr + align - 1) & !(align - 1);
    println!("after: {:#x}", aligned);
    aligned
}

fn align_down(addr: usize, align: usize) -> usize {
    println!("aligning {} to {}", addr, align);
    let aligned = addr & !(align - 1);
    println!("after: {}", aligned);
    aligned
}

fn pause(msg: &str) -> Result<(), Box<dyn Error>> {
    println!("Press enter to {}", msg);
    {
        let s = &mut String::new();
        stdin().read_line(s)?;
    }
    Ok(())
}

unsafe fn jmp(addr: *const u8) {
    let fptr: fn() = std::mem::transmute(addr);
    fptr();
}

fn ndisasm(input: &[u8], entry_offset: Addr) -> Result<(), Box<dyn Error>> {
    let mut proc = Command::new("ndisasm")
        .arg("-b")
        .arg("64")
        .arg("-s")
        .arg(entry_offset.0.to_string())
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    proc.stdin.as_mut().unwrap().write_all(input)?;
    let res = proc.wait_with_output()?;
    println!("{}", String::from_utf8_lossy(&res.stdout));
    Ok(())
}

impl From<&Vec<ProgramHeader>> for Table<'_> {
    fn from(headers: &Vec<ProgramHeader>) -> Self {
        let pheaders: Vec<Vec<String>> = headers
            .iter()
            .map(|ph| {
                let flags = &[
                    (SegmentFlags::Read, "R"),
                    (SegmentFlags::Write, "W"),
                    (SegmentFlags::Execute, "X"),
                ]
                .map(|(f, l)| if ph.flags.contains(f) { l } else { &"-" })
                .join(" ");
                vec![
                    format!("{:?}", ph.typ),
                    format!("{}", flags),
                    format!("{:?}", ph.mem_range()),
                    format!("{:?}", ph.file_range()),
                    format!("{:?}", ph.align),
                ]
            })
            .collect();
        Self {
            header: "Program Headers",
            labels: vec!["Type", "Flags", "Memory", "File", "Align"],
            rows: pheaders,
        }
    }
}

impl From<&File> for Table<'_> {
    fn from(file: &File) -> Self {
        Self {
            header: "File Header",
            labels: vec![
                "Type",
                "Architecture",
                "Entry Point",
                "Program Headers",
                "Section Headers",
            ],
            rows: vec![
                vec![
                    format!("{:?}", file.typ),
                    format!("{:?}", file.machine),
                    format!("{:?}", file.entry_point),
                    format!("Count: {:4}", file.prog_header_info.1),
                    format!("Count: {:4}", file.sect_header_info.1),
                ],
                vec![
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    format!("bytes: {:4}", file.prog_header_info.0),
                    format!("bytes: {:4}", file.sect_header_info.0),
                ],
            ],
        }
    }
}
