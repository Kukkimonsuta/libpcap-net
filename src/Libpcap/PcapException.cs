using System.Runtime.InteropServices;
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

    public static unsafe void ThrowIfNegativeStatus(int result, string method)
    {
        if (result < 0)
        {
            throw new PcapException(method, LibpcapNative.pcap_statustostr(result));
        }
    }

    public static unsafe void ThrowIfNonZeroStatus(int result, string method, Pcap pcap)
    {
        ThrowIfNonZeroStatus(result, method, pcap.Pointer);
    }

    internal static unsafe void ThrowIfNonZeroStatus(int result, string method, pcap* pcap)
    {
        if (result != 0)
        {
            var isError = result == LibpcapNative.PCAP_ERROR;

            if (isError)
            {
                if (pcap == null)
                {
                    throw new PcapException(method, "Unknown error");
                }

                var errorBuffer = LibpcapNative.pcap_geterr(pcap);

                throw new PcapException(method, errorBuffer);
            }
            else
            {
                var errorBuffer = LibpcapNative.pcap_statustostr(result);

                throw new PcapException(method, errorBuffer);
            }
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
