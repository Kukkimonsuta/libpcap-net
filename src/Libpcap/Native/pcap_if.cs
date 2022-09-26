namespace Libpcap.Native;

internal unsafe partial struct pcap_if
{
    [NativeTypeName("struct pcap_if *")]
    public pcap_if* next;

    [NativeTypeName("char *")]
    public sbyte* name;

    [NativeTypeName("char *")]
    public sbyte* description;

    [NativeTypeName("struct pcap_addr *")]
    public pcap_addr* addresses;

    [NativeTypeName("bpf_u_int32")]
    public uint flags;
}
