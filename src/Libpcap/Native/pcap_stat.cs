namespace Libpcap.Native;

internal partial struct pcap_stat
{
    [NativeTypeName("u_int")]
    public uint ps_recv;

    [NativeTypeName("u_int")]
    public uint ps_drop;

    [NativeTypeName("u_int")]
    public uint ps_ifdrop;

    [NativeTypeName("u_int")]
    public uint ps_capt;

    [NativeTypeName("u_int")]
    public uint ps_sent;

    [NativeTypeName("u_int")]
    public uint ps_netdrop;
}
