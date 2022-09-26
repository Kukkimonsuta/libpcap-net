using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using Libpcap.Native;

namespace Libpcap;

public readonly unsafe ref struct Packet
{
    private readonly pcap_pkthdr* _header;
    private readonly byte* _data;

    internal Packet(pcap_pkthdr* header, byte* data)
    {
        _header = header;
        _data = data;

        Data = new Span<byte>(data, CapturedLength);
    }

    internal pcap_pkthdr* HeaderPointer => _header;
    internal byte* DataPointer => _data;

    /// <summary>
    /// Declared packet length.
    /// </summary>
    public int DeclaredLength => (int)_header->len;

    /// <summary>
    /// Captured packet length. This is should always be lower or equal to <see cref="Pcap.SnapshotLength" />.
    /// </summary>
    public int CapturedLength => (int)_header->caplen;

    public Span<byte> Data { get; }

    public byte this[int index]
    {
        get
        {
            if (index < 0 || index >= CapturedLength)
                throw new ArgumentOutOfRangeException(nameof(index));

            return _data[index];
        }
    }
}

public enum Endianness
{
    Little,
    Big,
}

public ref struct PacketReader
{
    public PacketReader(ReadOnlySpan<byte> data, Endianness endianness = Endianness.Big)
    {
        Data = data;
        Endianness = endianness;
    }

    public ReadOnlySpan<byte> Data { get; }
    public Endianness Endianness { get; }

    public int Index { get; set; }
    public ReadOnlySpan<byte> Remainder => Data[Index..];

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Skip(int count)
    {
        if (Remainder.Length < count)
            throw new IndexOutOfRangeException(nameof(count));

        Index += count;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public short PeekByte()
    {
        if (Remainder.Length < 1)
            throw new IndexOutOfRangeException();

        return Remainder[0];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public short ReadByte()
    {
        var result = PeekByte();
        Index += 1;
        return result;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public short PeekInt16()
    {
        if (Remainder.Length < 2)
            throw new IndexOutOfRangeException();

        return Endianness == Endianness.Big ? BinaryPrimitives.ReadInt16BigEndian(Remainder) : BinaryPrimitives.ReadInt16LittleEndian(Remainder);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public short ReadInt16()
    {
        var result = PeekInt16();
        Index += 2;
        return result;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ushort PeekUInt16()
    {
        if (Remainder.Length < 2)
            throw new IndexOutOfRangeException();

        return Endianness == Endianness.Big ? BinaryPrimitives.ReadUInt16BigEndian(Remainder) : BinaryPrimitives.ReadUInt16LittleEndian(Remainder);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ushort ReadUInt16()
    {
        var result = PeekUInt16();
        Index += 2;
        return result;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int PeekInt32()
    {
        if (Remainder.Length < 4)
            throw new IndexOutOfRangeException();

        return Endianness == Endianness.Big ? BinaryPrimitives.ReadInt32BigEndian(Remainder) : BinaryPrimitives.ReadInt32LittleEndian(Remainder);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int ReadInt32()
    {
        var result = PeekInt32();
        Index += 4;
        return result;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public uint PeekUInt32()
    {
        if (Remainder.Length < 4)
            throw new IndexOutOfRangeException();

        return Endianness == Endianness.Big ? BinaryPrimitives.ReadUInt32BigEndian(Remainder) : BinaryPrimitives.ReadUInt32LittleEndian(Remainder);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public uint ReadUInt32()
    {
        var result = PeekUInt32();
        Index += 4;
        return result;
    }
}
