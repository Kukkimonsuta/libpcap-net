using System.Runtime.InteropServices;
using System.Text;
using Libpcap.Native;

namespace Libpcap;

public class PcapException : Exception
{
    public PcapException(string message)
        : base(message)
    {
    }
    public PcapException(string methodName, string errorMessage)
        : base($"Failed to call {methodName}: {errorMessage}")
    {
    }
    public unsafe PcapException(string methodName, sbyte* errorBuffer)
        : base($"Failed to call {methodName}: {Marshal.PtrToStringUTF8((IntPtr)errorBuffer)}")
    {
    }

    public static unsafe void ThrowStatus(int result, string method)
    {
        throw new PcapException(method, LibpcapNative.pcap_statustostr(result));
    }

    public static unsafe void ThrowIfNegativeStatus(int result, string method)
    {
        if (result < 0)
        {
            throw new PcapException(method, LibpcapNative.pcap_statustostr(result));
        }
    }

    public static void ThrowIfNegative(int result, string method, string errorMessage)
    {
        if (result < 0)
        {
            throw new PcapException(method, errorMessage);
        }
    }

    public static unsafe void ThrowIfNonZeroStatus(int result, string method)
    {
        if (result != 0)
        {
            throw new PcapException(method, LibpcapNative.pcap_statustostr(result));
        }
    }

    public static unsafe void ThrowIfNonZero(int result, string method, sbyte* errorBuffer)
    {
        if (result != 0)
        {
            throw new PcapException(method, errorBuffer);
        }
    }

    public static unsafe void ThrowIfNull(void* value, string method, sbyte* errorBuffer)
    {
        if (value == null)
        {
            throw new PcapException(method, errorBuffer);
        }
    }

    internal static unsafe void ThrowErrorIfNull(pcap* pcap, void* value, string method)
    {
        if (value == null)
        {
            throw new PcapException(method, LibpcapNative.pcap_geterr(pcap));
        }
    }
}
