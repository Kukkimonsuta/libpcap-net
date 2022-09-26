namespace Libpcap.Native;

internal partial struct pcap_file_header
{
    [NativeTypeName("bpf_u_int32")]
    public uint magic;

    [NativeTypeName("u_short")]
    public ushort version_major;

    [NativeTypeName("u_short")]
    public ushort version_minor;

    [NativeTypeName("bpf_int32")]
    public int thiszone;

    [NativeTypeName("bpf_u_int32")]
    public uint sigfigs;

    [NativeTypeName("bpf_u_int32")]
    public uint snaplen;

    [NativeTypeName("bpf_u_int32")]
    public uint linktype;
}
