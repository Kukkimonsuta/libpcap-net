namespace Libpcap.Native;

internal unsafe partial struct pcap_rmtauth
{
    public int type;

    [NativeTypeName("char *")]
    public sbyte* username;

    [NativeTypeName("char *")]
    public sbyte* password;
}
