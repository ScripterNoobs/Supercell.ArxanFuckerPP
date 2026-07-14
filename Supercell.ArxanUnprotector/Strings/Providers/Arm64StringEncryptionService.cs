namespace Supercell.ArxanUnprotector.Strings.Providers;

using System.Text;
using System;
using Supercell.ArxanUnprotector.Disassembler;
using Supercell.ArxanUnprotector.Ranges;
using Gee.External.Capstone.Arm;
using Gee.External.Capstone.Arm64;

public class Arm64StringEncryptionService : IStringEncryptionService
{
    public Library Library { get; set; }

    public RangeTable FindStringTable()
    {
        int decryptFunctionAddress = Library.InitFunctions.First();

        using (Arm64Disassembler disassembler = new Arm64Disassembler(true))
        {
            Span<byte> functionBytes = Library.Take(decryptFunctionAddress, 0x10000);

            foreach (Arm64Instruction instruction in disassembler.Iterate(functionBytes.ToArray(), decryptFunctionAddress))
            {
                if (instruction.Id is Arm64InstructionId.ARM64_INS_ADR or Arm64InstructionId.ARM64_INS_ADRP)
                {
                    Arm64Register destinationRegister = instruction.Details.Operands[0].Register;
                    Arm64Operand adrRegister = instruction.Details.Operands[1];

                    if (adrRegister.Type == Arm64OperandType.Immediate)
                    {
                        disassembler.Registers[destinationRegister.Id] = (int)adrRegister.Immediate;

                        if (RangeTableUtils.TryReadRangeTable(Library, disassembler.Registers[destinationRegister.Id], out RangeTable rangeTable) && rangeTable.Content.Length >= 0x10000)
                        {
                            return rangeTable;
                        }
                    }
                }
                else if (instruction.Id is Arm64InstructionId.ARM64_INS_ADD or Arm64InstructionId.ARM64_INS_SUB)
                {
                    Arm64Register destinationRegister = instruction.Details.Operands[0].Register;
                    Arm64Register sourceRegister = instruction.Details.Operands[1].Register;
                    Arm64Operand changeOperand = instruction.Details.Operands[2];

                    int sign = instruction.Id is Arm64InstructionId.ARM64_INS_ADD ? 1 : -1;

                    if (changeOperand.Type == Arm64OperandType.Immediate)
                    {
                        disassembler.Registers[destinationRegister.Id] = disassembler.Registers[sourceRegister.Id] +
                                                                         (int)changeOperand.Immediate * sign;
                    }
                    else if (changeOperand.Type == Arm64OperandType.Register)
                    {
                        disassembler.Registers[destinationRegister.Id] = disassembler.Registers[sourceRegister.Id] +
                                                                         disassembler.Registers[changeOperand.Register.Id] * sign;
                    }
                    else
                    {
                        throw new Exception("Unknown operand type");
                    }

                    if (RangeTableUtils.TryReadRangeTable(Library, disassembler.Registers[destinationRegister.Id], out RangeTable rangeTable) && rangeTable.Content.Length >= 0x10000)
                    {
                        return rangeTable;
                    }
                }
            }
        }

        throw new Exception("String table not found");
    }
    public void NullifyKey()
    {
        EncryptedStringKey key = FindKey(); // reuse your existing finder
        int keyAddr = key.Address;
        int keySize = key.Size; // looks like 128 in your constructor

        // Fill with 0x00
        byte[] zeros = new byte[keySize];
        for (int i = 0; i < zeros.Length; i++)
            zeros[i] = 0x00;

        //Library.Write(keyAddr, zeros);

        Console.WriteLine($"[*] Key at 0x{keyAddr:X} (size {keySize}) overwritten with nullbytes");
    }

    public EncryptedStringKey FindKey()
    {
        int decryptFunctionAddress = Library.InitFunctions.First();
        int potentialKeyAddress = 0;
        bool andDetected = false;

        using (Arm64Disassembler disassembler = new Arm64Disassembler(true))
        {
            Span<byte> functionBytes = Library.Take(decryptFunctionAddress, 0x10000);

            foreach (Arm64Instruction instruction in disassembler.Iterate(functionBytes.ToArray(), decryptFunctionAddress))
            {
                bool isPreviousInstructionIsPotentialKeyAddress = potentialKeyAddress != 0;

                if (instruction.Id is Arm64InstructionId.ARM64_INS_ADR or Arm64InstructionId.ARM64_INS_ADRP && andDetected)
                {
                    Arm64Register destinationRegister = instruction.Details.Operands[0].Register;
                    Arm64Operand adrRegister = instruction.Details.Operands[1];

                    if (adrRegister.Type == Arm64OperandType.Immediate)
                    {
                        disassembler.Registers[destinationRegister.Id] = potentialKeyAddress = (int)adrRegister.Immediate;
                        isPreviousInstructionIsPotentialKeyAddress = false;
                    }
                }
                else if (instruction.Id is Arm64InstructionId.ARM64_INS_ADD or Arm64InstructionId.ARM64_INS_SUB && andDetected)
                {
                    Arm64Register destinationRegister = instruction.Details.Operands[0].Register;
                    Arm64Register sourceRegister = instruction.Details.Operands[1].Register;
                    Arm64Operand changeOperand = instruction.Details.Operands[2];

                    int sign = instruction.Id is Arm64InstructionId.ARM64_INS_ADD ? 1 : -1;

                    if (changeOperand.Type == Arm64OperandType.Immediate)
                    {
                        disassembler.Registers[destinationRegister.Id] = disassembler.Registers[sourceRegister.Id] +
                                                                         (int)changeOperand.Immediate * sign;
                    }
                    else if (changeOperand.Type == Arm64OperandType.Register)
                    {
                        disassembler.Registers[destinationRegister.Id] = disassembler.Registers[sourceRegister.Id] +
                                                                         disassembler.Registers[changeOperand.Register.Id] * sign;
                    }
                    else
                    {
                        throw new Exception("Unknown operand type");
                    }

                    potentialKeyAddress = disassembler.Registers[destinationRegister.Id];
                }
                else if (instruction.Id == Arm64InstructionId.ARM64_INS_AND)
                {
                    if (instruction.Details.Operands[2] is { Type: Arm64OperandType.Immediate, Immediate: 127 })
                    {
                        if (andDetected)
                            throw new Exception("AND detected twice");

                        andDetected = true;
                    }
                }

                if (isPreviousInstructionIsPotentialKeyAddress)
                {
                    return new EncryptedStringKey(potentialKeyAddress, 128, Library);
                }
            }
        }

        throw new Exception("Key not found");
    }

    public void Compute(Span<byte> bytes)
    {
        Span<byte> key = Library.EncryptedStringKey.Content;

        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] ^= key[i % 128];
        }
    }
    public void RetEncryptor()
    {
        int decryptFunctionAddress = FindDecryptFunctionAddress();
        if (decryptFunctionAddress != 0)
        {
            Console.WriteLine($"[*] Found string decryption initializer automatically at 0x{decryptFunctionAddress:X8}. Patching...");
            Span<byte> functionBytes = Library.Take(decryptFunctionAddress, 0x4);
            functionBytes[0] = 0xC0;
            functionBytes[1] = 0x03;
            functionBytes[2] = 0x5F;
            functionBytes[3] = 0xD6;
        }
        else
        {
            Console.WriteLine("[!] Warning: Could not automatically locate string decryption initializer.");
        }
    }

    private int FindDecryptFunctionAddress()
    {
        // 1. Locate wutf8Table address
        int tableAddr = -1;
        ReadOnlySpan<byte> memSpan = Library.Take(0);
        int lookupOffset = memSpan.IndexOf(Library.Wutf8Table.AsSpan());
        if (lookupOffset != -1)
        {
            tableAddr = lookupOffset;
        }

        if (tableAddr == -1)
            return 0;

        // 2. Scan code segment for ADRP+ADD instructions referencing tableAddr
        int pageTarget = tableAddr & ~0xFFF;
        int offsetTarget = tableAddr & 0xFFF;

        // Approximate code section (.text)
        Span<byte> codeSection = Library.GetSection(SectionType.Text, out int codeAddress);
        
        using (Arm64Disassembler disassembler = new Arm64Disassembler(true))
        {
            // We search for ADRP to target page
            for (int offset = 0; offset < codeSection.Length - 24; offset += 4)
            {
                uint val = BitConverter.ToUInt32(codeSection.Slice(offset, 4));
                if ((val & 0x9F000000) == 0x90000000)
                {
                    // Decode ADRP immediate
                    uint immlo = (val >> 29) & 3;
                    uint immhi = (val >> 5) & 0x7FFFF;
                    long imm = (immhi << 2) | immlo;
                    if ((imm & 0x100000) != 0)
                        imm -= 0x200000;
                    
                    int pc = codeAddress + offset;
                    long addr = (pc & ~0xFFF) + imm * 4096;
                    if (addr == pageTarget)
                    {
                        // Check if next instruction is ADD referencing tableAddr
                        uint nextVal = BitConverter.ToUInt32(codeSection.Slice(offset + 4, 4));
                        if ((nextVal & 0xFFC00000) == 0x91000000) // ADD (immediate)
                        {
                            uint imm12 = (nextVal >> 10) & 0xFFF;
                            if (imm12 == offsetTarget)
                            {
                                // We found the reference inside the function!
                                // Scan backward for the start of the function (common ARM64 prologue stp x29, x30, [sp, ...])
                                // Let's scan backward up to 0x500 bytes for function boundaries.
                                for (int scan = offset; scan >= Math.Max(0, offset - 0x500); scan -= 4)
                                {
                                    uint testVal = BitConverter.ToUInt32(codeSection.Slice(scan, 4));
                                    // Match stp xN, xM, [sp, ...] or ret
                                    if ((testVal & 0xFFC00000) == 0xA9000000 || testVal == 0xD65F03C0)
                                    {
                                        int funcAddr = codeAddress + (testVal == 0xD65F03C0 ? scan + 4 : scan);
                                        return funcAddr;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return 0;
    }
}