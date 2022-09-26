using System.Diagnostics.CodeAnalysis;
using System.Net;
using Libpcap.Native;

namespace Libpcap;

public abstract unsafe class PcapAddress
{
    public PcapAddressFamily Family { get; }

    internal PcapAddress(PcapAddressFamily family, [DisallowNull] sockaddr* address)
    {
        Family = family;
        if (address == null)
            throw new ArgumentNullException(nameof(address));
        RawFamily = address->sa_family;
    }

    public ushort RawFamily { get; }

    #region Static members

    public static PcapAddressFamily GetPcapAddressFamily(ushort nativeFamily)
    {
#if WIN_X86 || WIN_X64
        return nativeFamily switch
        {
            1 /* AF_UNIX */ => PcapAddressFamily.Unix,
            2 /* AF_INET */ => PcapAddressFamily.IPv4,
            23 /* AF_INET6 */ => PcapAddressFamily.IPv6,
            _ => PcapAddressFamily.Unknown
        };
#else
        return nativeFamily switch
        {
            1 /* AF_UNIX */ => PcapAddressFamily.Unix,
            2 /* AF_INET */ => PcapAddressFamily.IPv4,
            10 /* AF_INET6 */ => PcapAddressFamily.IPv6,
            _ => PcapAddressFamily.Unknown
        };
#endif
    }

    internal static PcapAddress FromSockAddr([DisallowNull] sockaddr* address)
    {
        var family = GetPcapAddressFamily(address->sa_family);

        return family switch
        {
            PcapAddressFamily.Unix => new PcapUnixAddress(address),
            PcapAddressFamily.IPv4 => new PcapIPv4Address(address),
            PcapAddressFamily.IPv6 => new PcapIPv6Address(address),
            _ => new PcapUnknownAddress(address),
        };
    }

    #endregion
}

public unsafe class PcapUnknownAddress : PcapAddress
{
    internal PcapUnknownAddress([DisallowNull] sockaddr* address)
        : base(PcapAddressFamily.Unknown, address)
    {
    }
}

public unsafe class PcapUnixAddress : PcapAddress
{
    internal PcapUnixAddress([DisallowNull] sockaddr* address)
        : base(PcapAddressFamily.Unix, address)
    {
    }
}

public abstract unsafe class PcapIPAddress : PcapAddress
{
    internal PcapIPAddress(PcapAddressFamily family, [DisallowNull] sockaddr* address)
        : base(family, address)
    {
    }

    public abstract IPAddress Address { get; }
}

public unsafe class PcapIPv4Address : PcapIPAddress
{
    internal PcapIPv4Address([DisallowNull] sockaddr* address)
        : base(PcapAddressFamily.IPv4, address)
    {
        var addressIn = (sockaddr_in*)address;

        Address = new IPAddress(*(long*)addressIn->sin_addr);
    }

    public override IPAddress Address { get; }
}

public unsafe class PcapIPv6Address : PcapIPAddress
{
    internal PcapIPv6Address([DisallowNull] sockaddr* address)
        : base(PcapAddressFamily.IPv6, address)
    {
        var addressIn6 = (sockaddr_in6*)address;

        Address = new IPAddress(new ReadOnlySpan<byte>(addressIn6->sin6_addr, 16), addressIn6->sin6_scope_id);
    }

    public override IPAddress Address { get; }
}
