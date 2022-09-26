namespace Libpcap.Native;

internal unsafe partial struct pcap_addr
{
    [NativeTypeName("struct pcap_addr *")]
    public pcap_addr* next;

    [NativeTypeName("struct sockaddr *")]
    public sockaddr* addr;

    [NativeTypeName("struct sockaddr *")]
    public sockaddr* netmask;

    [NativeTypeName("struct sockaddr *")]
    public sockaddr* broadaddr;

    [NativeTypeName("struct sockaddr *")]
    public sockaddr* dstaddr;
}
