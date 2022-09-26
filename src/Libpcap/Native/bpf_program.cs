namespace Libpcap.Native;

internal unsafe partial struct bpf_program
{
    [NativeTypeName("u_int")]
    public uint bf_len;

    [NativeTypeName("struct bpf_insn *")]
    public bpf_insn* bf_insns;
}
