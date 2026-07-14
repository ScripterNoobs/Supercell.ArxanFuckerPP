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

                // Check if the Section Header Table (SHT) is corrupted/obfuscated (e.g. out of file boundaries)
                ulong totalShtSize = (ulong)shnum * shentsize;
                bool isShtCorrupted = shoff > 0 && (shoff + totalShtSize > (ulong)fileBytes.Length || shnum > 1000);

                // Additional check: Verify if all section offsets inside SHT are valid and within file bounds
                if (!isShtCorrupted && shoff > 0 && shnum > 0)
                {
                    for (int i = 0; i < shnum; i++)
                    {
                        ulong sectionHeaderAddr = shoff + (ulong)i * shentsize;
                        if (sectionHeaderAddr + 40 <= (ulong)fileBytes.Length)
                        {
                            ulong sectionOffset = BitConverter.ToUInt64(fileBytes, (int)sectionHeaderAddr + 24);
                            ulong sectionSize = BitConverter.ToUInt64(fileBytes, (int)sectionHeaderAddr + 32);
                            uint sectionType = BitConverter.ToUInt32(fileBytes, (int)sectionHeaderAddr + 4);
                            
                            // A valid section (except SHT_NULL/SHT_NOBITS) must have its offset + size within the file
                            if (sectionType != 0 && sectionType != 8 && sectionOffset + sectionSize > (ulong)fileBytes.Length)
                            {
                                isShtCorrupted = true;
                                break;
                            }
                        }
                    }
                }

                if (isShtCorrupted)
                {
                    Console.WriteLine($"[*] Detected corrupted/encrypted section header table in {Path.GetFileName(path)}. Nullifying section headers to force program-header fallback loading...");
                    // Nullify shoff (offset 40, 8 bytes), shnum (offset 60, 2 bytes), shstrndx (offset 62, 2 bytes)
                    byte[] zero8 = new byte[8];
                    byte[] zero2 = new byte[2];
                    Array.Copy(zero8, 0, fileBytes, 40, 8);
                    Array.Copy(zero2, 0, fileBytes, 60, 2);
                    Array.Copy(zero2, 0, fileBytes, 62, 2);
                    isPatched = true;
                }
                else if (shnum > 0 && shstrndx < shnum)
                {
                    ulong strTableSectionHeaderAddr = shoff + (ulong)shstrndx * shentsize;
                    if (strTableSectionHeaderAddr + 8 <= (ulong)fileBytes.Length)
                    {
                        uint sectionType = BitConverter.ToUInt32(fileBytes, (int)strTableSectionHeaderAddr + 4);
                        if (sectionType != 3) // 3 = SHT_STRTAB
                        {
                            Console.WriteLine($"[*] Automatically repairing corrupted shstrndx type (0x{sectionType:X8} -> 0x3) on disk for {Path.GetFileName(path)}...");
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