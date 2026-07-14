namespace Supercell.ArxanUnprotector.Ranges;

using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Supercell.ArxanUnprotector;

public class RangeTable
{
    public const int EntrySize = 32;
    
    public int StartAddress { get; }
    public int EndAddress { get; }
    
    public Library Library { get; }

    // Lazy loaded
    private List<RangeTableEntry> _entries;
    private RangeTableChecksum? _entriesChecksum;
    private List<RangeTableChecksumLocation> _entriesChecksumLocations;

    public RangeTable(int startAddress, int endAddress, Library library)
    {
        StartAddress = startAddress;
        EndAddress = endAddress;
        Library = library;

        _entries = null;
        _entriesChecksum = null;
        _entriesChecksumLocations = null;
    }
    
    public void InvalidateCache()
    {
        _entries = null;
        _entriesChecksum = null;
        _entriesChecksumLocations = null;
    }

    public Span<byte> Content => Library.Take(StartAddress, EndAddress - StartAddress);

    public List<RangeTableEntry> Entries
    {
        get
        {
            _entries ??= GetEntries();
            return _entries;
        }
    }

    public RangeTableChecksum Checksum
    {
        get
        {
            _entriesChecksum ??= CalculateChecksum();
            return _entriesChecksum.Value;
        }
    }

    public List<RangeTableChecksumLocation> ChecksumLocations
    {
        get
        {
            _entriesChecksumLocations ??= FindChecksumLocation();
            return _entriesChecksumLocations;
        }
    }

    private List<RangeTableEntry> GetEntries()
    {
        List<RangeTableEntry> entries = new List<RangeTableEntry>();
        Span<byte> data = Content;
            
        do
        {
            ParseRange(data, StartAddress, out int address, out int length);
                
            if (length == 0)
                break;
                
            entries.Add(new RangeTableEntry(address, length, Library));
            data = data.Slice(EntrySize);
        } while (true);
            
        return entries;
    }

    private RangeTableChecksum CalculateChecksum()
    {
        RangeTableChecksum checksum = new RangeTableChecksum();
        List<RangeTableEntry> entries = Entries;

        for (int i = 0; i < entries.Count; i++)
        {
            entries[i].CalculateChecksum(ref checksum);
        }

        return checksum;
    }

    private List<RangeTableChecksumLocation> FindChecksumLocation()
    {
        RangeTableChecksum checksum = Checksum;

        List<RangeTableChecksumLocation> locations = new List<RangeTableChecksumLocation>();

        List<int> key1Addresses = Library.GetValueAddresses(checksum.Key1);
        List<int> key2Addresses = Library.GetValueAddresses(checksum.Key2);
        List<int> key3Addresses = Library.GetValueAddresses(checksum.Key3);

        if (key1Addresses.Count == key2Addresses.Count && key2Addresses.Count == key3Addresses.Count)
        {
            for (int i = 0; i < key1Addresses.Count; i++)
            {
                locations.Add(new RangeTableChecksumLocation(key1Addresses[i], key2Addresses[i], key3Addresses[i]));
            }   
        }

        return locations;
    }

    
    public override string ToString()
    {
        return $"RangeTable({StartAddress:x8}-{EndAddress:x8})";
    }

    public static void ParseRange(ReadOnlySpan<byte> data, int tableAddress, out int address, out int size)
    {
        if (data.Length < EntrySize)
            throw new Exception("Invalid range table entry");
        
        ulong id = BitConverter.ToUInt64(data.Slice(0, 8));
        ulong startPtr = BitConverter.ToUInt64(data.Slice(8, 8));
        ulong endPtr = BitConverter.ToUInt64(data.Slice(16, 8));
        ulong checksumPtr = BitConverter.ToUInt64(data.Slice(24, 8));

        // In Supercell ELF files:
        // Pointers are virtual addresses mapped to segments.
        // The base load address (virtual address of the library segments) in ELF is 0.
        // However, Arxan RangeTable virtual address pointers are absolute within the ELF virtual address layout (usually around 0x1750000 or similar).
        // Since load base is 0, startPtr is exactly the ELF virtual address.
        // We mask the high bits (metadata/tags) to get the clean ELF virtual address.
        ulong startAddr = startPtr & 0xFFFFFFFFFFUL;
        ulong endAddr = endPtr & 0xFFFFFFFFFFUL;

        address = (int)startAddr;
        size = (int)(endAddr - startAddr);
    }
}