namespace Libpcap.Native;

internal unsafe partial struct pcap_send_queue
{
    [NativeTypeName("u_int")]
    public uint maxlen;

    [NativeTypeName("u_int")]
    public uint len;

    [NativeTypeName("char *")]
    public sbyte* buffer;
}
