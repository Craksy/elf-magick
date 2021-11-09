use std::{
    env,
    error::Error,
    fs,
    io::{stdin, Write},
    mem::transmute,
    process::{self, Command, Stdio},
    slice::from_raw_parts_mut,
};

use carpenter::*;
use delf::{types::*, FileHeader};
use mmap::{MapOption, MemoryMap};
use region::{protect, Protection};

fn main() -> Result<(), Box<dyn Error>> {
    let base = 0x400000usize;
    let path = env::args().nth(1).expect("Usage: elk <file_path>");
    let input = fs::read(&path)?;
    if let Some(file) = FileHeader::parse_or_print_error(&input[..]) {
        println!("Disassembling {}...", &path);
        let prog_header = file
            .program_headers
            .iter()
            .find(|ph| ph.mem_range().contains(&file.entry_point))
            .expect("entry point not found in program headers");
        let code = &prog_header.data;
        ndisasm(code, file.entry_point)?;

        let rela_entries = &file.read_rela_entries().unwrap_or_else(|e| {
            println!("couldn't read entries: {:?}", e);
            Default::default()
        });
        file.print();
        ProgramHeader::print_table(&file.program_headers);
        if let Some(ds) = file
            .program_headers
            .iter()
            .find(|h| h.typ == delf::types::SegmentType::Dynamic)
        {
            if let delf::types::SegmentContent::Dynamic(ref table) = ds.contents {
                DynamicEntry::print_table(&table);
            }
            RelaEntry::print_table(rela_entries);
        }

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
            let addr: *mut u8 = aligned as _;
            println!(
                "Mapping segment at {:?} with {:?}. Address: {:p}",
                memory_range, ph.flags, addr
            );
            let map = MemoryMap::new(
                ph.mem_size.0 as usize + padding,
                &[MapOption::MapWritable, MapOption::MapAddr(addr)],
            )?;

            println!("Copy segment data to memory region...");
            {
                let dst = unsafe { from_raw_parts_mut(addr.add(padding), ph.data.len()) };
                dst.copy_from_slice(&ph.data[..]);
            }

            for reloc in rela_entries {
                if ph.mem_range().contains(&reloc.offset) {
                    unsafe {
                        let segment_start = addr.add(padding);
                        let segment_offset = reloc.offset - ph.mem_range().start;
                        println!("Apply {:?} relocation at {:?}", reloc.typ, segment_offset);
                        let reloc_addr: *mut u64 =
                            transmute(segment_start.add(segment_offset.into()));
                        match reloc.typ {
                            RelType::Relative => {
                                let val = reloc.addend + Addr(base as u64);
                                *reloc_addr = val.0;
                            }
                            _ => {
                                panic!("Unsupported type {:?}", &reloc.typ)
                            }
                        }
                    }
                }
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
            mappings.push(map);
        }

        let code_ptr = code.as_ptr();
        unsafe {
            protect(code_ptr, code.len(), Protection::READ_WRITE_EXECUTE)?;
        }

        println!("Jumping to entry point: {:?}", file.entry_point);

        unsafe { jmp((file.entry_point.0 as usize + base) as _) };
    } else {
        process::exit(1);
    }

    Ok(())
}

fn _align_up(addr: usize, align: usize) -> usize {
    let aligned = (addr + align - 1) & !(align - 1);
    aligned
}

fn align_down(addr: usize, align: usize) -> usize {
    let aligned = addr & !(align - 1);
    aligned
}

fn _pause(msg: &str) -> Result<(), Box<dyn Error>> {
    println!("Press enter to {}", msg);
    {
        let s = &mut String::new();
        stdin().read_line(s)?;
    }
    Ok(())
}

unsafe fn jmp(addr: *const u8) {
    let fptr: fn() = transmute(addr);
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
