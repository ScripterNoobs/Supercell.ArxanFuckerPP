namespace Supercell.ArxanUnprotector;

using System.Diagnostics;
using Supercell.ArxanUnprotector.Ranges.Providers;
using Supercell.ArxanUnprotector.Strings.Providers;
using ELFSharp.ELF;
using ELFSharp.ELF.Sections;
using ELFSharp.ELF.Segments;
using System.Net.Sockets;

public class Android64Library : Library
{
    private readonly IELF _elf;
    private readonly int _initArrayAddress = 0;
    private readonly int _initArraySize = 0;
    private readonly int _finiArrayAddress = 0;
    private readonly int _finiArraySize = 0;
    private int _relaOffset = 0;
    private int _relaSize = 0;
    private int _relaEntrySize = 24; // default is 24 for Elf64_Rela

    public Android64Library(string path) : base(new GenericMemoryRangeTableProvider(), new Arm64StringEncryptionService())
    {
        _elf = ELFReader.Load(path);
        _fileData = File.ReadAllBytes(path);

        _memoryData = new byte[_elf.Segments.Where(x => x.Type == SegmentType.Load).Cast<Segment<ulong>>().Max(s => s.Address + s.Size)];

        if (_elf.Sections.Count > 0)
        {
            foreach (ISection section in _elf.Sections)
            {
                if (section is Section<ulong> bitSection && bitSection.Type != ELFSharp.ELF.Sections.SectionType.NoBits)
                {
                    _fileData.AsSpan((int) bitSection.Offset, (int) bitSection.Size).CopyTo(_memoryData.AsSpan((int) bitSection.LoadAddress, (int) bitSection.Size));
                }
            }
        }
        else
        {
            // If section headers are missing, map PT_LOAD segments directly to _memoryData
            var loads = _elf.Segments.Where(x => x.Type == SegmentType.Load).Cast<Segment<ulong>>().ToList();
            foreach (var load in loads)
            {
                int srcOffset = (int)load.Offset;
                int size = (int)load.Size;
                int dstAddress = (int)load.Address;
                
                if (srcOffset + size <= _fileData.Length)
                {
                    _fileData.AsSpan(srcOffset, size).CopyTo(_memoryData.AsSpan(dstAddress, size));
                }
            }
        }

        // Parse Dynamic Segment manually from mapped memoryData (since it is decrypted in memory)
        var dynamicSegment = _elf.Segments.FirstOrDefault(x => x.Type == SegmentType.Dynamic) as Segment<ulong>;
        if (dynamicSegment != null)
        {
            int dynAddress = (int)dynamicSegment.Address;
            int dynSize = (int)dynamicSegment.Size;
            for (int j = 0; j < dynSize; j += 16)
            {
                if (dynAddress + j + 16 > _memoryData.Length) break;
                long tag = BitConverter.ToInt64(_memoryData, dynAddress + j);
                ulong val = BitConverter.ToUInt64(_memoryData, dynAddress + j + 8);
                if (tag == 0) break; // DT_NULL
                if (tag == 25) _initArrayAddress = (int)val; // DT_INIT_ARRAY
                if (tag == 27) _initArraySize = (int)val;    // DT_INIT_ARRAYSZ
                if (tag == 26) _finiArrayAddress = (int)val; // DT_FINI_ARRAY
                if (tag == 28) _finiArraySize = (int)val;    // DT_FINI_ARRAYSZ
                if (tag == 7) _relaOffset = (int)val;        // DT_RELA
                if (tag == 8) _relaSize = (int)val;          // DT_RELASZ
                if (tag == 9) _relaEntrySize = (int)val;      // DT_RELAENT
            }
        }
        
        MakeRelocation();
        MakeRelocationAddends();
        
        _elf.Dispose();
    }

    public override IEnumerable<int> InitFunctions
    {
        get
        {
            List<int> addresses = new List<int>();
            if (_elf.Sections.Any(s => s.Name == ".init_array"))
            {
                Span<byte> data = GetSectionByName(".init_array", out _);
                Debug.Assert(data.Length % 8 == 0);
                while (!data.IsEmpty)
                {
                    addresses.Add((int) BitConverter.ToInt64(data));
                    data = data.Slice(8);
                }
            }
            else if (_initArrayAddress != 0 && _initArraySize > 0)
            {
                Span<byte> data = _memoryData.AsSpan(_initArrayAddress, _initArraySize);
                while (!data.IsEmpty)
                {
                    addresses.Add((int) BitConverter.ToInt64(data));
                    data = data.Slice(8);
                }
            }
            return addresses;
        }
    }

    public override IEnumerable<int> FiniFunctions
    {
        get
        {
            List<int> addresses = new List<int>();
            if (_elf.Sections.Any(s => s.Name == ".fini_array"))
            {
                Span<byte> data = GetSectionByName(".fini_array", out _);
                Debug.Assert(data.Length % 8 == 0);
                while (!data.IsEmpty)
                {
                    addresses.Add((int) BitConverter.ToInt64(data));
                    data = data.Slice(8);
                }
            }
            else if (_finiArrayAddress != 0 && _finiArraySize > 0)
            {
                Span<byte> data = _memoryData.AsSpan(_finiArrayAddress, _finiArraySize);
                while (!data.IsEmpty)
                {
                    addresses.Add((int) BitConverter.ToInt64(data));
                    data = data.Slice(8);
                }
            }
            return addresses;
        }
    }

    public override int SectionCount => _elf.Sections.Count;

    public override Span<byte> GetSection(SectionType type, out int address)
    {
        string name = type switch
        {
            SectionType.Data => ".data",
            SectionType.Text => ".text",
            _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
        };
        
        if (_elf.Sections.Any(s => s.Name == name))
        {
            return GetSectionByName(name, out address);
        }
        else
        {
            // If section headers are missing, we approximate .text and .data based on segment flags!
            // Usually, .text is in RX segment, .data is in RW segment.
            // Let's find the PT_LOAD segments.
            var loads = _elf.Segments.Where(x => x.Type == SegmentType.Load).Cast<Segment<ulong>>().ToList();
            if (type == SectionType.Text)
            {
                // Find RX load segment
                var rxLoad = loads.FirstOrDefault(l => (l.Flags & SegmentFlags.Execute) != 0);
                if (rxLoad != null)
                {
                    address = (int)rxLoad.Address;
                    return _memoryData.AsSpan((int)rxLoad.Address, (int)rxLoad.Size);
                }
            }
            else if (type == SectionType.Data)
            {
                // Find RW load segment (usually the last or containing DT_DYNAMIC)
                var rwLoad = loads.FirstOrDefault(l => (l.Flags & SegmentFlags.Write) != 0 && (l.Flags & SegmentFlags.Execute) == 0);
                if (rwLoad != null)
                {
                    address = (int)rwLoad.Address;
                    return _memoryData.AsSpan((int)rwLoad.Address, (int)rwLoad.Size);
                }
            }
            throw new Exception($"Could not approximate section {type}");
        }
    }
    
    public override Span<byte> GetSectionAt(int index, out int address)
    {
        Section<ulong> section = (Section<ulong>) _elf.GetSection(index);
        address = (int) section.LoadAddress;
        return _memoryData.AsSpan((int) section.LoadAddress, (int) section.Size);
    }

    private Span<byte> GetSectionByName(string name, out int address)
    {
        Section<ulong> section = (Section<ulong>) _elf.GetSection(name);
        address = (int) section.LoadAddress;
        return _memoryData.AsSpan((int) section.LoadAddress, (int) section.Size);
    }

    public override Span<byte> Take(int address)
    {
        if (address < 0 || address > _memoryData.Length)
            throw new ArgumentOutOfRangeException(nameof(address));

        return _memoryData.AsSpan(address);
    }

    public override Span<byte> Take(int address, int length)
    {
        if (address < 0 || address > _memoryData.Length)
            throw new ArgumentOutOfRangeException(nameof(address));

        return _memoryData.AsSpan(address, length);
    }

    public override void Save(string filePath)
    {
        // Write back based on PT_LOAD segment offsets and virtual addresses
        var loads = _elf.Segments.Where(x => x.Type == SegmentType.Load).Cast<Segment<ulong>>().ToList();
        foreach (var load in loads)
        {
            int srcOffset = (int)load.Address;
            int size = (int)load.Size;
            int dstOffset = (int)load.Offset;

            if (dstOffset + size <= _fileData.Length)
            {
                Array.Copy(_memoryData, srcOffset, _fileData, dstOffset, size);
            }
        }
        
        File.WriteAllBytes(filePath, _fileData);
    }

    private void MakeRelocation()
    {
        SymbolTable<ulong> symbolTable = _elf.Sections.OfType<SymbolTable<ulong>>().FirstOrDefault();

        if (_elf.Sections.Any(s => s.Type == ELFSharp.ELF.Sections.SectionType.Relocation))
        {
            foreach (Section<ulong> section in _elf.Sections.Where(s => s.Type == ELFSharp.ELF.Sections.SectionType.Relocation).Cast<Section<ulong>>())
            {
                byte[] data = section.GetContents();

                for (int i = 0; i < data.Length; i += 16)
                {
                    ulong offset = BitConverter.ToUInt64(data, i);
                    ulong info = BitConverter.ToUInt64(data, i + 8);
                    
                    ulong symbolIndex = info >> 8;
                    ulong type = info & 0xFF;

                    if (type == 2 && symbolTable != null)
                    {
                        SymbolEntry<ulong> symbol = symbolTable.Entries.ElementAt((int) symbolIndex);
                        
                        _memoryData[offset] = (byte) (symbol.Value);
                        _memoryData[offset + 1] = (byte) (symbol.Value >> 8);
                        _memoryData[offset + 2] = (byte) (symbol.Value >> 16);
                        _memoryData[offset + 3] = (byte) (symbol.Value >> 24);
                        _memoryData[offset + 4] = (byte) (symbol.Value >> 32);
                        _memoryData[offset + 5] = (byte) (symbol.Value >> 40);
                        _memoryData[offset + 6] = (byte) (symbol.Value >> 48);
                        _memoryData[offset + 7] = (byte) (symbol.Value >> 56);
                    }
                }
            }
        }
    }

    private void MakeRelocationAddends()
    {
        SymbolTable<ulong> symbolTable = _elf.Sections.OfType<SymbolTable<ulong>>().FirstOrDefault();

        if (_elf.Sections.Any(s => s.Type == ELFSharp.ELF.Sections.SectionType.RelocationAddends))
        {
            foreach (Section<ulong> section in _elf.Sections.Where(s => s.Type == ELFSharp.ELF.Sections.SectionType.RelocationAddends).Cast<Section<ulong>>())
            {
                byte[] data = section.GetContents();
                ApplyRelaData(data, symbolTable);
            }
        }
        else if (_relaOffset != 0 && _relaSize > 0)
        {
            // Convert virtual address _relaOffset to file offset
            var loads = _elf.Segments.Where(x => x.Type == SegmentType.Load).Cast<Segment<ulong>>().ToList();
            var relaSeg = loads.FirstOrDefault(l => (ulong)_relaOffset >= l.Address && (ulong)_relaOffset < l.Address + l.Size);
            if (relaSeg != null)
            {
                int fileOffset = (int)((ulong)_relaOffset - relaSeg.Address + (ulong)relaSeg.Offset);
                byte[] data = _fileData.AsSpan(fileOffset, _relaSize).ToArray();
                ApplyRelaData(data, symbolTable);
            }
        }
    }

    private void ApplyRelaData(byte[] data, SymbolTable<ulong> symbolTable)
    {
        for (int i = 0; i < data.Length; i += _relaEntrySize)
        {
            if (i + 24 > data.Length) break;
            ulong offset = BitConverter.ToUInt64(data, i);
            ulong info = BitConverter.ToUInt64(data, i + 8);
            ulong addend = BitConverter.ToUInt64(data, i + 16);
            
            uint symbolIndex = (uint) (info >> 32);
            uint type = (uint) (info & 0xFFFFFFFF);

            switch (type)
            {
                case 1027: // R_AARCH64_RELATIVE
                    _memoryData[offset] = (byte) (addend);
                    _memoryData[offset + 1] = (byte) (addend >> 8);
                    _memoryData[offset + 2] = (byte) (addend >> 16);
                    _memoryData[offset + 3] = (byte) (addend >> 24);
                    _memoryData[offset + 4] = (byte) (addend >> 32);
                    _memoryData[offset + 5] = (byte) (addend >> 40);
                    _memoryData[offset + 6] = (byte) (addend >> 48);
                    _memoryData[offset + 7] = (byte) (addend >> 56);
                    break;
                case 257: // R_AARCH64_ABS64
                    if (symbolTable != null)
                    {
                        SymbolEntry<ulong> symbol = symbolTable.Entries.ElementAt((int) symbolIndex);
                    
                        _memoryData[offset] = (byte) (symbol.Value);
                        _memoryData[offset + 1] = (byte) (symbol.Value >> 8);
                        _memoryData[offset + 2] = (byte) (symbol.Value >> 16);
                        _memoryData[offset + 3] = (byte) (symbol.Value >> 24);
                        _memoryData[offset + 4] = (byte) (symbol.Value >> 32);
                        _memoryData[offset + 5] = (byte) (symbol.Value >> 40);
                        _memoryData[offset + 6] = (byte) (symbol.Value >> 48);
                        _memoryData[offset + 7] = (byte) (symbol.Value >> 56);
                    }
                    break;
            }
        }
    }

    public override HashSet<int> GetRelocationOffsets()
    {
        HashSet<int> offsets = new HashSet<int>();
        SymbolTable<ulong> symbolTable = _elf.Sections.OfType<SymbolTable<ulong>>().FirstOrDefault();

        if (_elf.Sections.Any(s => s.Type == ELFSharp.ELF.Sections.SectionType.Relocation))
        {
            foreach (Section<ulong> section in _elf.Sections.Where(s => s.Type == ELFSharp.ELF.Sections.SectionType.Relocation).Cast<Section<ulong>>())
            {
                byte[] data = section.GetContents();
                for (int i = 0; i < data.Length; i += 16)
                {
                    ulong offset = BitConverter.ToUInt64(data, i);
                    for (int r = 0; r < 8; r++)
                        offsets.Add((int)offset + r);
                }
            }
        }

        if (_elf.Sections.Any(s => s.Type == ELFSharp.ELF.Sections.SectionType.RelocationAddends))
        {
            foreach (Section<ulong> section in _elf.Sections.Where(s => s.Type == ELFSharp.ELF.Sections.SectionType.RelocationAddends).Cast<Section<ulong>>())
            {
                byte[] data = section.GetContents();
                for (int i = 0; i < data.Length; i += _relaEntrySize)
                {
                    if (i + 24 > data.Length) break;
                    ulong offset = BitConverter.ToUInt64(data, i);
                    for (int r = 0; r < 8; r++)
                        offsets.Add((int)offset + r);
                }
            }
        }
        else if (_relaOffset != 0 && _relaSize > 0)
        {
            var loads = _elf.Segments.Where(x => x.Type == SegmentType.Load).Cast<Segment<ulong>>().ToList();
            var relaSeg = loads.FirstOrDefault(l => (ulong)_relaOffset >= l.Address && (ulong)_relaOffset < l.Address + l.Size);
            if (relaSeg != null)
            {
                int fileOffset = (int)((ulong)_relaOffset - relaSeg.Address + (ulong)relaSeg.Offset);
                byte[] data = _fileData.AsSpan(fileOffset, _relaSize).ToArray();
                for (int i = 0; i < data.Length; i += _relaEntrySize)
                {
                    if (i + 24 > data.Length) break;
                    ulong offset = BitConverter.ToUInt64(data, i);
                    for (int r = 0; r < 8; r++)
                        offsets.Add((int)offset + r);
                }
            }
        }

        return offsets;
    }
}