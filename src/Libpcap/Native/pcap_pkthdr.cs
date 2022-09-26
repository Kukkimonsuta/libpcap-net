namespace Libpcap.Native;

internal partial struct pcap_pkthdr
{
    [NativeTypeName("struct timeval")]
    public timeval ts;

    [NativeTypeName("bpf_u_int32")]
    public uint caplen;

    [NativeTypeName("bpf_u_int32")]
    public uint len;
}
