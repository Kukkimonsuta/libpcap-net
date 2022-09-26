namespace Libpcap.Native;

internal partial struct bpf_insn
{
    [NativeTypeName("u_short")]
    public ushort code;

    [NativeTypeName("u_char")]
    public byte jt;

    [NativeTypeName("u_char")]
    public byte jf;

    [NativeTypeName("bpf_u_int32")]
    public uint k;
}
