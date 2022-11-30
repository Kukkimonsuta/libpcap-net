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

        Data = new ReadOnlySpan<byte>(data, CapturedLength);
    }

    internal pcap_pkthdr* HeaderPointer => _header;
    internal byte* DataPointer => _data;

    public DateTime Timestamp =>
#if REFERENCE_ASSEMBLY
        // this is just placeholder for reference assemblies
        throw new PlatformNotSupportedException();
#else
        DateTime.UnixEpoch.AddSeconds(_header->ts.tv_sec).AddMicroseconds(_header->ts.tv_usec);
#endif

    /// <summary>
    /// Declared packet length.
    /// </summary>
    public int DeclaredLength => (int)_header->len;

    /// <summary>
    /// Captured packet length. This is should always be lower or equal to <see cref="Pcap.DeclaredLength" />.
    /// </summary>
    public int CapturedLength => (int)_header->caplen;

    public ReadOnlySpan<byte> Data { get; }

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
