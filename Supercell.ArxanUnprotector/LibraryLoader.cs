namespace Supercell.ArxanUnprotector;

using ELFSharp.ELF;


public static class LibraryLoader
{
    public static Library Load(string path)
    {
        try
        {
            if (ELFReader.TryLoad(path, out var elf))
                return LoadElf(path, elf);
        }
        catch (Exception)
        {
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