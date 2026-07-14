namespace Supercell.ArxanUnprotector;

using System.Diagnostics;
using Supercell.ArxanUnprotector.Ranges.Providers;
using Supercell.ArxanUnprotector.Strings.Providers;
using ELFSharp.MachO;

public class iOSFATLibrary : Library
{
    private readonly MachO _macho;
    private readonly long _imageBase;

    public iOSFATLibrary(string path)
        : base(new GenericMemoryRangeTableProvider(), new Arm64StringEncryptionService())
    {
        _fileData = File.ReadAllBytes(path);

        using var fs = File.OpenRead(path);
        var machos = MachOReader.LoadFat(fs, true);

        // Pragmatic FAT selection:
        // 1) prefer 64-bit
        // 2) fall back to last slice
        _macho = machos.FirstOrDefault(m => m.Is64)
              ?? machos.Last();

        var segments = _macho
            .GetCommandsOfType<Segment>()
            .Where(s => s.Address != 0 && s.Size != 0)
            .ToArray();

        ulong minAddr = segments.Min(s => s.Address);
        ulong maxAddr = segments.Max(s => s.Address + s.Size);
        ulong size = maxAddr - minAddr;

        if (size > int.MaxValue)
            throw new InvalidOperationException("Mach-O image too large to map");

        _imageBase = (long)minAddr;
        _memoryData = new byte[(int)size];

        foreach (var segment in segments)
        {
            foreach (var section in segment.Sections)
            {
                int dst = (int)(section.Address - minAddr);
                int src = (int)section.Offset;
                int len = (int)section.Size;

                _fileData.AsSpan(src, len)
                         .CopyTo(_memoryData.AsSpan(dst, len));
            }
        }
    }



    public override IEnumerable<int> InitFunctions
    {
        get
        {
            Span<byte> data = GetSectionByName("__mod_init_func", out _);
            Debug.Assert(data.Length % 8 == 0);
            List<int> addresses = new List<int>(data.Length / 8);

            while (!data.IsEmpty)
            {
                addresses.Add((int) BitConverter.ToInt64(data));
                data = data.Slice(8);
            }
            
            return addresses;
        }
    }

    public override IEnumerable<int> FiniFunctions => throw new NotSupportedException();
    
    public override int SectionCount => _macho.GetCommandsOfType<Section>().Count();

    public override Span<byte> GetSection(SectionType section, out int address)
    {
        string name = section switch
        {
            SectionType.Data => "__data",
            SectionType.Text => "__text",
            _ => throw new ArgumentOutOfRangeException(nameof(section), section, null)
        };
        
        return GetSectionByName(name, out address);
    }

    public override Span<byte> GetSectionAt(int index, out int address)
    {
        Section section = _macho.GetCommandsOfType<Section>().ElementAt(index);
        address = (int) section.Address;
        return _memoryData.AsSpan(address, (int) section.Size);
    }

    private Span<byte> GetSectionByName(string name, out int address)
    {
        Section section = _macho.GetCommandsOfType<Segment>().SelectMany(s => s.Sections).Single(s => s.Name == name);

        address = (int) section.Address;
        return _memoryData.AsSpan(address, (int) section.Size);
    }

    private int Rebase(int address) => address - (int)_imageBase;

    public override Span<byte> Take(int address)
    {
        int offset = address - (int)_imageBase;
        if ((uint)offset >= _memoryData.Length)
            return Span<byte>.Empty;

        return _memoryData.AsSpan(offset);
    }

    public override Span<byte> Take(int address, int length)
    {
        int offset = address - (int)_imageBase;
        if (offset < 0 || offset + length > _memoryData.Length)
            return Span<byte>.Empty;

        return _memoryData.AsSpan(offset, length);
    }


    public override void Save(string filePath)
    {
        foreach (Section section in _macho.GetCommandsOfType<Segment>().Where(s => s.Address != 0).SelectMany(s => s.Sections))
        {
            if (section.Name is "__data" or "__text")
            {
                Array.Copy(_memoryData, (int) section.Address, _fileData, (int) section.Offset, (int) section.Size);
            }
        }
        
        File.WriteAllBytes(filePath, _fileData);
    }

    public override HashSet<int> GetRelocationOffsets()
    {
        return new HashSet<int>();
    }
}