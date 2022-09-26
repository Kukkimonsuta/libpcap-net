using System.Reflection;
using System.Runtime.InteropServices;

namespace Libpcap.Native;

internal partial class LibpcapNative
{
    // source: https://www.pinvoke.net/default.aspx/kernel32.setdlldirectory
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetDllDirectory(string lpPathName);

    static LibpcapNative()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            SetDllDirectory(Path.Combine(Environment.SystemDirectory, "Npcap"));
        }

        NativeLibrary.SetDllImportResolver(typeof(LibpcapNative).Assembly, Resolver);
    }

    public static IntPtr Resolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != "pcap")
        {
            // Use default resolver
            return IntPtr.Zero;
        }

        var paths = new List<string>()
        {
            libraryName,
        };

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            paths.Add("wpcap");
        }

        foreach (var path in paths)
        {
            if (NativeLibrary.TryLoad(path, assembly, searchPath, out var handle))
            {
                return handle;
            }
        }

        return IntPtr.Zero;
    }
}
