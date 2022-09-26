using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Libpcap.Native;

[assembly: InternalsVisibleTo("Libpcap.Tests")]

namespace Libpcap;

public abstract unsafe class Pcap : IDisposable
{
    internal pcap* _pcap;

    internal Pcap([DisallowNull] pcap* pcap)
    {
        if (pcap == null)
            throw new ArgumentNullException(nameof(pcap));
        _pcap = pcap;
    }

    ~Pcap()
    {
        Dispose(false);
    }

    public abstract string Name { get; }

    internal pcap* Pointer
    {
        get
        {
            CheckDisposed();

            return _pcap;
        }
    }

    private bool _immediateMode;

    /// <summary>
    /// Sets whether immediate mode should be set on a capture handle when the handle is activated. In immediate mode, packets are always delivered as soon as they arrive, with no buffering. See <a href="https://www.tcpdump.org/manpages/pcap_set_immediate_mode.3pcap.html">pcap_set_immediate_mode.3pcap.html</a>.
    /// </summary>
    public bool ImmediateMode
    {
        get
        {
            CheckDisposed();

            return _immediateMode;
        }
        set
        {
            CheckDisposed();

            var result = LibpcapNative.pcap_set_immediate_mode(_pcap, value ? 1 : 0);
            PcapException.ThrowIfNonZero(result, "pcap_set_immediate_mode", LibpcapNative.pcap_statustostr(result));

            _immediateMode = value;
        }
    }

    private int _bufferSize;

    /// <summary>
    /// Sets the buffer size that will be used on a capture handle when the handle is activated to buffer_size, which is in units of bytes. See <a href="https://www.tcpdump.org/manpages/pcap_set_buffer_size.3pcap.html">pcap_set_buffer_size.3pcap.html</a>.
    /// </summary>
    public int BufferSize
    {
        get
        {
            CheckDisposed();

            return _bufferSize;
        }
        set
        {
            CheckDisposed();

            var result = LibpcapNative.pcap_set_buffer_size(_pcap, value);
            PcapException.ThrowIfNonZero(result, "pcap_set_buffer_size", LibpcapNative.pcap_statustostr(result));

            _bufferSize = value;
        }
    }

    /// <summary>
    /// Gets or set the link-layer header type to be used by a capture device. See <a href="https://www.tcpdump.org/manpages/pcap_datalink.3pcap.html">pcap_datalink.3pcap.html</a> or <a href="https://www.tcpdump.org/manpages/pcap_set_datalink.3pcap.html">pcap_set_datalink.3pcap.html</a>.
    /// </summary>
    public PcapDataLink DataLink
    {
        get
        {
            CheckDisposed();

            var result = LibpcapNative.pcap_datalink(_pcap);
            PcapException.ThrowIfNegativeStatus(result, "pcap_datalink");

            return (PcapDataLink)result;
        }
        set
        {
            CheckDisposed();

            var result = LibpcapNative.pcap_set_datalink(_pcap, (int)value);
            PcapException.ThrowIfNonZeroStatus(result, "pcap_set_datalink");
        }
    }

    // TODO: https://www.tcpdump.org/manpages/pcap_set_protocol_linux.3pcap.html

    // TODO: https://www.tcpdump.org/manpages/pcap_set_rfmon.3pcap.html

    // TODO: https://www.tcpdump.org/manpages/pcap_set_tstamp_precision.3pcap.html

    // TODO: https://www.tcpdump.org/manpages/pcap_set_tstamp_type.3pcap.html

    // TODO: https://www.tcpdump.org/manpages/pcap_setdirection.3pcap.html

    // TODO: https://www.tcpdump.org/manpages/pcap_setfilter.3pcap.html

    public PcapActivateResult Activate(bool throwOnError = true, bool throwOnWarning = false)
    {
        var result = (PcapActivateResult)LibpcapNative.pcap_activate(_pcap);

        if (throwOnError && result < 0)
        {
            var errorBuffer = LibpcapNative.pcap_geterr(_pcap);
            var errorMessage = Marshal.PtrToStringUTF8((IntPtr)errorBuffer) ?? result.ToString();

            throw new PcapException("pcap_activate", errorMessage);
        }

        if (throwOnWarning && result > 0)
        {
            var warningBuffer = LibpcapNative.pcap_geterr(_pcap);
            var warningMessage = Marshal.PtrToStringUTF8((IntPtr)warningBuffer) ?? result.ToString();

            throw new PcapException("pcap_activate", warningMessage);
        }

        return result;
    }

    public void Loop(int count, PacketCallback callback)
    {
        var context = new PcapDispatchContext
        {
            Pcap = this,
            Callback = callback,
        };

        var contextHandle = GCHandle.Alloc(context);
        try
        {
            var result = LibpcapNative.pcap_loop(_pcap, count, &DispatchHelper.PacketCallback, (byte*)GCHandle.ToIntPtr(contextHandle));
            if (result == LibpcapNative.PCAP_ERROR_BREAK)
            {
                return;
            }

            PcapException.ThrowIfNegativeStatus(result, "pcap_loop");
        }
        finally
        {
            contextHandle.Free();
        }
    }

    public int Dispatch(int count, PacketCallback callback)
    {
        var context = new PcapDispatchContext
        {
            Pcap = this,
            Callback = callback,
        };

        var contextHandle = GCHandle.Alloc(context);
        try
        {
            var result = LibpcapNative.pcap_dispatch(_pcap, count, &DispatchHelper.PacketCallback, (byte*)GCHandle.ToIntPtr(contextHandle));
            if (result == LibpcapNative.PCAP_ERROR_BREAK)
            {
                return 0;
            }

            PcapException.ThrowIfNegativeStatus(result, "pcap_dispatch");

            return result;
        }
        finally
        {
            contextHandle.Free();
        }
    }

    #region IDisposable

    // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
    internal bool IsDisposed => _pcap == null;

    internal void CheckDisposed()
    {
        if (IsDisposed)
            throw new ObjectDisposedException("Pcap");
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_pcap != null)
        {
            LibpcapNative.pcap_close(_pcap);
            _pcap = null;
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

    public static readonly Version Version_1_9_0 = new(1, 9, 0);
    public static readonly Version Version_1_10_0 = new(1, 10, 0);

    static Pcap()
    {
        // documentation says it's available since 1.9.0, but in reality it seem to be since 1.10.0
        if (Version >= Version_1_10_0)
        {
            var result = 0;
            var errorBuffer = stackalloc sbyte[LibpcapNative.PCAP_ERRBUF_SIZE];

            result = LibpcapNative.pcap_init(LibpcapNative.PCAP_CHAR_ENC_UTF_8, errorBuffer);
            PcapException.ThrowIfNonZero(result, "pcap_init", errorBuffer);
        }
    }

    private static string? _versionString;
    public static string VersionString
    {
        get
        {
            if (_versionString == null)
            {
                var buffer = LibpcapNative.pcap_lib_version();
                if (buffer == null)
                    throw new InvalidOperationException("Failed to get libpcap version");

                _versionString = Marshal.PtrToStringUTF8((IntPtr)buffer) ?? throw new InvalidOperationException("Failed to read libpcap version");
            }

            return _versionString;
        }
    }

    private static Version? _version;
    public static Version Version
    {
        get
        {
            if (_version == null)
            {
                // Npcap version 1.60, based on libpcap version 1.10.2-PRE-GIT
                // libpcap version 1.9.1 (with TPACKET_V3)
                // libpcap version 1.9.1

                var match = Regex.Match(VersionString, @"libpcap version (?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)(?:-(?<metadata>[\S]+))?");
                if (!match.Success)
                    throw new InvalidOperationException($"Failed to parse libpcap version '{VersionString}'");

                var major = int.Parse(match.Groups["major"].ValueSpan);
                var minor = int.Parse(match.Groups["minor"].ValueSpan);
                var patch = int.Parse(match.Groups["patch"].ValueSpan);

                _version = new Version(major, minor, patch);
            }

            return _version;
        }
    }

    public static PcapDeviceList ListDevices()
    {
        var result = 0;
        var errorBuffer = stackalloc sbyte[LibpcapNative.PCAP_ERRBUF_SIZE];

        pcap_if* devices;
        result = LibpcapNative.pcap_findalldevs(&devices, errorBuffer);
        PcapException.ThrowIfNonZero(result, "pcap_findalldevs", errorBuffer);
        try
        {
            return new PcapDeviceList(devices);
        }
        finally
        {
            LibpcapNative.pcap_freealldevs(devices);
        }
    }

    public static DevicePcap OpenDevice(PcapDevice device)
    {
        var errorBuffer = stackalloc sbyte[LibpcapNative.PCAP_ERRBUF_SIZE];

        Span<byte> nameBuffer = stackalloc byte[Encoding.UTF8.GetMaxByteCount(device.Name.Length) + 1];
        var nameBufferLength = Encoding.UTF8.GetBytes(device.Name, nameBuffer);
        // it's not clear whether stackalloc always zeroes the memory, so let's make sure it's a null terminated string
        // https://github.com/dotnet/runtime/issues/4384#issuecomment-124003439
        nameBuffer[nameBufferLength] = 0;

        fixed (byte* pNameBuffer = nameBuffer)
        {
            var pcap = LibpcapNative.pcap_create((sbyte*)pNameBuffer, errorBuffer);
            PcapException.ThrowIfNull(pcap, "pcap_create", errorBuffer);

            return new DevicePcap(device, pcap);
        }
    }

    public static FileReadPcap OpenFileRead(string path, PcapTimestampPrecision precision = PcapTimestampPrecision.Microsecond)
    {
        var errorBuffer = stackalloc sbyte[LibpcapNative.PCAP_ERRBUF_SIZE];

        Span<byte> pathBuffer = stackalloc byte[Encoding.UTF8.GetMaxByteCount(path.Length) + 1];
        var nameBufferLength = Encoding.UTF8.GetBytes(path, pathBuffer);
        // it's not clear whether stackalloc always zeroes the memory, so let's make sure it's a null terminated string
        // https://github.com/dotnet/runtime/issues/4384#issuecomment-124003439
        pathBuffer[nameBufferLength] = 0;

        fixed (byte* pPathBuffer = pathBuffer)
        {
            var pcap = LibpcapNative.pcap_open_offline((sbyte*)pPathBuffer, errorBuffer);
            PcapException.ThrowIfNull(pcap, "pcap_open_offline", errorBuffer);

            return new FileReadPcap(pcap, path);
        }
    }

    public static FileWritePcap OpenFileWrite(string path, PcapDataLink linkType, int snapshotLength, PcapTimestampPrecision precision = PcapTimestampPrecision.Microsecond, bool append = false)
    {
        var errorBuffer = stackalloc sbyte[LibpcapNative.PCAP_ERRBUF_SIZE];

        Span<byte> pathBuffer = stackalloc byte[Encoding.UTF8.GetMaxByteCount(path.Length) + 1];
        var nameBufferLength = Encoding.UTF8.GetBytes(path, pathBuffer);
        // it's not clear whether stackalloc always zeroes the memory, so let's make sure it's a null terminated string
        // https://github.com/dotnet/runtime/issues/4384#issuecomment-124003439
        pathBuffer[nameBufferLength] = 0;

        fixed (byte* pPathBuffer = pathBuffer)
        {
            var pcap = LibpcapNative.pcap_open_dead_with_tstamp_precision((int)linkType, snapshotLength, (uint)precision);
            PcapException.ThrowIfNull(pcap, "pcap_open_offline", errorBuffer);

            var dumper = append ? LibpcapNative.pcap_dump_open_append(pcap, (sbyte*)pPathBuffer) : LibpcapNative.pcap_dump_open(pcap, (sbyte*)pPathBuffer);
            PcapException.ThrowErrorIfNull(pcap, dumper, "pcap_dump_open");

            return new FileWritePcap(pcap, path, dumper);
        }
    }

    #endregion
}

public enum PcapTimestampPrecision
{
    Microsecond = LibpcapNative.PCAP_TSTAMP_PRECISION_MICRO,
    Nanosecond = LibpcapNative.PCAP_TSTAMP_PRECISION_NANO,
}

public unsafe class DevicePcap : Pcap
{
    public PcapDevice Device { get; }
    public override string Name => $"Device: {Device.Description ?? Device.Name}";

    internal DevicePcap(PcapDevice device, pcap* pcap)
        : base(pcap)
    {
        Device = device ?? throw new ArgumentNullException(nameof(device));

        SnapshotLength = 65535;
        PromiscuousMode = false;
        Timeout = 100;
        ImmediateMode = false;
        BufferSize = 512 * 1024 * 1024; // 512 KiB
    }

    private int _snapshotLength;

    /// <summary>
    /// Set the snapshot length for a not-yet-activated capture handle. See <a href="https://www.tcpdump.org/manpages/pcap_set_snaplen.3pcap.html">pcap_set_snaplen.3pcap.html</a>.
    /// </summary>
    public int SnapshotLength
    {
        get
        {
            CheckDisposed();

            return _snapshotLength;
        }
        set
        {
            CheckDisposed();

            var result = LibpcapNative.pcap_set_snaplen(_pcap, value);
            PcapException.ThrowIfNonZero(result, "pcap_set_snaplen", LibpcapNative.pcap_statustostr(result));

            _snapshotLength = value;
        }
    }

    private bool _promiscuousMode;

    /// <summary>
    /// Set promiscuous mode for a not-yet-activated capture handle. See <a href="https://www.tcpdump.org/manpages/pcap_set_promisc.3pcap.html">pcap_set_promisc.3pcap.html</a>.
    /// </summary>
    public bool PromiscuousMode
    {
        get
        {
            CheckDisposed();

            return _promiscuousMode;
        }
        set
        {
            CheckDisposed();

            var result = LibpcapNative.pcap_set_promisc(_pcap, value ? 1 : 0);
            PcapException.ThrowIfNonZero(result, "pcap_set_promisc", LibpcapNative.pcap_statustostr(result));

            _promiscuousMode = value;
        }
    }

    private int _timeout;

    /// <summary>
    /// Set the packet buffer timeout for a not-yet-activated capture handle. See <a href="https://www.tcpdump.org/manpages/pcap_set_timeout.3pcap.html">pcap_set_timeout.3pcap.html</a>.
    /// </summary>
    public int Timeout
    {
        get
        {
            CheckDisposed();

            return _timeout;
        }
        set
        {
            CheckDisposed();

            var result = LibpcapNative.pcap_set_timeout(_pcap, value);
            PcapException.ThrowIfNonZero(result, "pcap_set_timeout", LibpcapNative.pcap_statustostr(result));

            _timeout = value;
        }
    }

    /// <summary>
    /// Sets whether immediate mode should be set on a capture handle when the handle is activated. In immediate mode, packets are always delivered as soon as they arrive, with no buffering. See <a href="https://www.tcpdump.org/manpages/pcap_setnonblock.3pcap.html">pcap_setnonblock.3pcap.html</a>.
    /// </summary>
    public bool NonBlocking
    {
        get
        {
            CheckDisposed();

            var result = 0;
            var errorBuffer = stackalloc sbyte[LibpcapNative.PCAP_ERRBUF_SIZE];

            result = LibpcapNative.pcap_getnonblock(_pcap, errorBuffer);

            if (result == 0)
            {
                return false;
            }

            if (result > 0)
            {
                return true;
            }

            throw new PcapException("pcap_getnonblock", errorBuffer);
        }
        set
        {
            CheckDisposed();

            var result = 0;
            var errorBuffer = stackalloc sbyte[LibpcapNative.PCAP_ERRBUF_SIZE];

            result = LibpcapNative.pcap_setnonblock(_pcap, value ? 1 : 0, errorBuffer);
            PcapException.ThrowIfNonZero(result, "pcap_setnonblock", errorBuffer);
        }
    }
}

public class FileReadPcap : Pcap
{
    public string Path { get; }
    public override string Name => $"File (reading {Path})";

    internal unsafe FileReadPcap(pcap* pcap, string path)
        : base(pcap)
    {
        Path = path ?? throw new ArgumentNullException(nameof(path));
    }
}

public unsafe class FileWritePcap : Pcap
{
    public string Path { get; }
    public override string Name => $"File (writing {Path})";
    private pcap_dumper* _dumper;

    internal FileWritePcap(pcap* pcap, string path, [DisallowNull] pcap_dumper* dumper)
        : base(pcap)
    {
        Path = path ?? throw new ArgumentNullException(nameof(path));
        if (dumper == null)
            throw new ArgumentNullException(nameof(dumper));
        _dumper = dumper;
    }

    public void Write(ref Packet packet)
    {
        LibpcapNative.pcap_dump((byte*)_dumper, packet.HeaderPointer, packet.DataPointer);
    }

    protected override void Dispose(bool disposing)
    {
        if (_dumper != null)
        {
            LibpcapNative.pcap_dump_close(_dumper);
            _dumper = null;
        }

        base.Dispose(disposing);
    }
}
