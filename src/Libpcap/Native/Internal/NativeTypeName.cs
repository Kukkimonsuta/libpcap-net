namespace Libpcap.Native;

/// <summary>
/// Dummy type, should be always used only as a pointer target.
/// </summary>
internal struct _iobuf
{
}

/// <summary>
/// This type has variable length, should be always used only as a pointer target.
/// </summary>
internal unsafe struct sockaddr
{
    /// <summary>
    /// address family, AF_xxx
    /// </summary>
    public ushort sa_family;

    /// <summary>
    /// 14 bytes of protocol address
    /// </summary>
    public fixed byte sa_data[14];
}

internal unsafe struct sockaddr_in
{
    /// <summary>
    /// address family: AF_INET
    /// </summary>
    public ushort sin_family;
    /// <summary>
    /// port in network byte order
    /// </summary>
    public ushort sin_port;
    /// <summary>
    /// internet address
    /// </summary>
    public fixed byte sin_addr[4];
}

internal unsafe struct sockaddr_in6
{
    /// <summary>
    /// address family, AF_INET6
    /// </summary>
    public ushort sin6_family;

    /// <summary>
    /// port number, Network Byte Order
    /// </summary>
    public ushort sin6_port;

    /// <summary>
    /// IPv6 flow information
    /// </summary>
    public uint sin6_flowinfo;

    /// <summary>
    /// IPv6 address
    /// </summary>
    public fixed byte sin6_addr[16];

    /// <summary>
    /// Scope ID
    /// </summary>
    public uint sin6_scope_id;
}
