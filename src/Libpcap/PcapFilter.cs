using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Text;
using Libpcap.Native;

namespace Libpcap;

public unsafe class PcapFilter : IDisposable
{
    internal bpf_program* pointer;

    public string Expression { get; }

    private PcapFilter(string? expression)
    {
        Expression = expression ?? throw new ArgumentNullException(nameof(expression));

        pointer = (bpf_program*)Marshal.AllocHGlobal(sizeof(bpf_program));
    }

    ~PcapFilter()
    {
        Dispose(false);
    }

    #region

    // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
    internal bool IsDisposed => pointer == null;

    internal void CheckDisposed()
    {
        if (IsDisposed)
            throw new ObjectDisposedException("PcapFilter");
    }

    protected virtual void Dispose(bool disposing)
    {
        if (pointer != null)
        {
            LibpcapNative.pcap_freecode(pointer);
            Marshal.FreeHGlobal((IntPtr)pointer);
            pointer = null;
        }

        if (disposing)
        {
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    #endregion

    #region Static members

    public static PcapFilter Create(Pcap pcap, string? expression, bool optimize = true, uint? netmask = null)
    {
        pcap.CheckDisposed();

        var filter = new PcapFilter(expression);

        Span<byte> expressionBuffer = stackalloc byte[Encoding.UTF8.GetMaxByteCount((expression ?? "").Length) + 1];
        var expressionBufferLength = Encoding.UTF8.GetBytes(expression ?? "", expressionBuffer);
        // it's not clear whether stackalloc always zeroes the memory, so let's make sure it's a null terminated string
        // https://github.com/dotnet/runtime/issues/4384#issuecomment-124003439
        expressionBuffer[expressionBufferLength] = 0;

        fixed (byte* pExpressionBuffer = expressionBuffer)
        {
            var result = LibpcapNative.pcap_compile(pcap.Pointer, filter.pointer, (sbyte*)pExpressionBuffer, optimize ? 1 : 0, netmask ?? LibpcapNative.PCAP_NETMASK_UNKNOWN);
            PcapException.ThrowIfNonZeroStatus(result, "pcap_compile", pcap);
        }

        return filter;
    }

    #endregion
}
