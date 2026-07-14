public static class MachODetector
{
    private const uint MH_MAGIC = 0xFEEDFACE;
    private const uint MH_MAGIC_64 = 0xFEEDFACF;
    private const uint MH_CIGAM = 0xCEFAEDFE;
    private const uint MH_CIGAM_64 = 0xCFFAEDFE;
    private const uint FAT_MAGIC = 0xCAFEBABE;
    private const uint FAT_CIGAM = 0xBEBAFECA;

    public static MachOInfo Read(string path)
    {
        using var fs = File.OpenRead(path);
        using var br = new BinaryReader(fs);

        uint magic = br.ReadUInt32();

        return magic switch
        {
            MH_MAGIC or MH_CIGAM => new MachOInfo(false, false),
            MH_MAGIC_64 or MH_CIGAM_64 => new MachOInfo(true, false),
            FAT_MAGIC or FAT_CIGAM => new MachOInfo(false, true),
            _ => throw new InvalidDataException("Not a Mach-O binary")
        };
    }
}

public record MachOInfo(bool Is64Bit, bool IsFat);
