using System.Runtime.InteropServices;

namespace Libpcap.Native;

// win x32:      4 + 4
// win x64:      4 + 4
// linux x64:    8 + 8
// osx x64:      8 + 4
[StructLayout(LayoutKind.Sequential)]
public struct timeval
{
    /// <summary>
    /// Time interval, in seconds.
    /// </summary>
#if WIN_X86 || WIN_X64
    public int tv_sec;
#elif OSX_X64
    public long tv_sec;
#elif LINUX_X64
    public long tv_sec;
#elif REFERENCE_ASSEMBLY
#else
    #error Unsupported platform.
#endif

    /// <summary>
    /// Time interval, in microseconds.
    /// </summary>
#if WIN_X86 || WIN_X64
    public int tv_usec;
#elif OSX_X64
    public int tv_usec;
#elif LINUX_X64
    public long tv_usec;
#elif REFERENCE_ASSEMBLY
#else
    #error Unsupported platform.
#endif
};
