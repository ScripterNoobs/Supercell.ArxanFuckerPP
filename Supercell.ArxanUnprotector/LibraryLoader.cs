namespace Supercell.ArxanUnprotector;

using ELFSharp.ELF;


public static class LibraryLoader
{
    public static Library Load(string path)
    {
        try
        {
            byte[] fileBytes = File.ReadAllBytes(path);
            bool isPatched = false;
            
            // Check for ELF magic: 7F 45 4C 46
            if (fileBytes.Length >= 64 && fileBytes[0] == 0x7F && fileBytes[1] == 0x45 && fileBytes[2] == 0x4C && fileBytes[3] == 0x46)
            {
                // Parse ELF64 header fields
                ulong shoff = BitConverter.ToUInt64(fileBytes, 40);
                ushort shentsize = BitConverter.ToUInt16(fileBytes, 58);
                ushort shnum = BitConverter.ToUInt16(fileBytes, 60);
                ushort shstrndx = BitConverter.ToUInt16(fileBytes, 62);

                if (shnum > 0 && shstrndx < shnum)
                {
                    ulong strTableSectionHeaderAddr = shoff + (ulong)shstrndx * shentsize;
                    if (strTableSectionHeaderAddr + 8 <= (ulong)fileBytes.Length)
                    {
                        uint sectionType = BitConverter.ToUInt32(fileBytes, (int)strTableSectionHeaderAddr + 4);
                        if (sectionType != 3) // 3 = SHT_STRTAB
                        {
                            Console.WriteLine($"[*] Automatically repairing corrupted shstrndx type (0x{sectionType:X8} -> 0x3) on disk for {Path.GetFileName(path)}...");
                            // Patch the section type to SHT_STRTAB (3)
                            byte[] patchedTypeBytes = BitConverter.GetBytes((uint)3);
                            Array.Copy(patchedTypeBytes, 0, fileBytes, (int)strTableSectionHeaderAddr + 4, 4);
                            isPatched = true;
                        }
                    }
                }
            }

            if (isPatched)
            {
                File.WriteAllBytes(path, fileBytes);
            }

            if (ELFReader.TryLoad(path, out var elf))
            {
                return LoadElf(path, elf);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] ELFReader error for {path}: {ex}");
        }

        try
        {
            var mach = MachODetector.Read(path);

            if (mach.IsFat)
                //return new iOSFATLibrary(path);
                throw new NotSupportedException("Fat Mach-O not supported yet");

            return mach.Is64Bit
                ? new iOS64Library(path):
                //: new iOS32Library(path);
                throw new NotSupportedException("32-bit Mach-O not supported yet");
        }
        catch (InvalidDataException ex)
        {
            Console.WriteLine(ex);
        }

        throw new NotSupportedException("Unknown binary format");
    }

    private static Library LoadElf(string path, IELF elf)
    {
        return elf.Class switch
        {
            Class.Bit32 => new AndroidLibrary(path),
            Class.Bit64 => new Android64Library(path),
            _ => throw new NotSupportedException("Unsupported ELF class")
        };
    }

}