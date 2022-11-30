using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Libpcap.Native;

namespace Libpcap;

internal class PcapDispatchContext
{
    public Pcap Pcap = null!;
    public int Count = 0;
    public PacketCallback Callback = null!;
}

/// <summary>
/// Manages listening to multiple pcaps.
/// </summary>
public unsafe class PcapDispatcher : IDisposable
{
    private readonly PcapDispatchContext _context = new();
    private GCHandle _contextHandle;

    public PacketCallback Callback
    {
        get => _context.Callback;
        set => _context.Callback = value;
    }

    private string? _filter;
    public string? Filter
    {
        get
        {
            CheckDisposed();

            return _filter;
        }
        set
        {
            CheckDisposed();

            foreach (var pcap in _pcaps)
            {
                pcap.Filter = value;
            }
            _filter = value;
        }
    }

    private int _rotateAfter;
    public int RotateAfter
    {
        get => _rotateAfter;
        set
        {
            if (value <= 0)
                throw new ArgumentOutOfRangeException(nameof(value));

            _rotateAfter = value;
        }
    }

    private List<Pcap> _pcaps = new();
    private int _pcapIndex;
    private int _pcapCount;

    /// <summary>
    /// Create new pcap dispatcher.
    /// </summary>
    /// <param name="callback">Method to be called when packet is received.</param>
    /// <param name="rotateAfter">Continue with next device after this many packets even if it could possibly return more.</param>
    public PcapDispatcher(PacketCallback callback, int rotateAfter = 50)
    {
        Callback = callback ?? throw new ArgumentNullException(nameof(callback));
        if (rotateAfter <= 0)
            throw new ArgumentOutOfRangeException(nameof(rotateAfter));
        RotateAfter = rotateAfter;

        _contextHandle = GCHandle.Alloc(_context);
    }

    /// <summary>
    /// Create new pcap, configure and activate it.
    /// </summary>
    public void OpenDevice(PcapDevice device, Action<DevicePcap>? configure = null)
    {
        CheckDisposed();

        var pcap = Pcap.OpenDevice(device);
        try
        {
            configure?.Invoke(pcap);

            pcap.Activate();
            pcap.NonBlocking = true;
            if (_filter != null)
            {
                pcap.Filter = _filter;
            }

            _pcaps.Add(pcap);
        }
        catch
        {
            pcap.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Create new pcap reading from file, configure and activate it.
    /// </summary>
    public void OpenFile(string path, Action<FileReadPcap>? configure = null)
    {
        CheckDisposed();

        var pcap = Pcap.OpenFileRead(path);
        try
        {
            configure?.Invoke(pcap);
            if (_filter != null)
            {
                pcap.Filter = _filter;
            }

            _pcaps.Add(pcap);
        }
        catch
        {
            pcap.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Dispatch given number of packets from tracked pcaps.
    /// </summary>
    public int Dispatch(int count)
    {
        CheckDisposed();

        if (_pcaps.Count <= 0)
        {
            return 0;
        }

        var attemptedPcapCount = 0;
        var readPacketCount = 0;

        void SetNextPcap()
        {
            attemptedPcapCount += 1;
            _pcapIndex += 1;
            if (_pcapIndex >= _pcaps.Count)
            {
                _pcapIndex = 0;
            }
            _pcapCount = 0;
        }

        while (true)
        {
            // Check if we've tried all devices already
            if (attemptedPcapCount >= _pcaps.Count)
            {
                break;
            }

            // Check if we've read all requested packets
            var expectedPacketCount = count - readPacketCount;
            if (expectedPacketCount <= 0)
            {
                break;
            }

            // Check if we need to move over to next pcap
            var expectedPacketCountFromPcap = Math.Min(RotateAfter - _pcapCount, expectedPacketCount);
            if (expectedPacketCountFromPcap <= 0)
            {
                SetNextPcap();
                continue;
            }

            var pcap = _pcaps[_pcapIndex];
            pcap.CheckDisposed();

            _context.Pcap = pcap;
            _context.Count = 0;

            var result = LibpcapNative.pcap_dispatch(pcap.Pointer, expectedPacketCountFromPcap, &DispatchHelper.PacketCallback, (byte*)GCHandle.ToIntPtr(_contextHandle));
            if (result == LibpcapNative.PCAP_ERROR_BREAK)
            {
                break;
            }
            PcapException.ThrowIfNegativeStatus(result, "pcap_dispatch");

            // "result" is 0 in case when packets were read but file doesn't contain any more, so we need to count them ourselves
            readPacketCount += _context.Count;
            _pcapCount += result;

            if (result != expectedPacketCountFromPcap)
            {
                SetNextPcap();
            }
        }

        return readPacketCount;
    }

    #region IDisposable

    // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
    internal bool IsDisposed => _pcaps == null;

    internal void CheckDisposed()
    {
        if (IsDisposed)
            throw new ObjectDisposedException("PcapDeviceList");
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            if (_contextHandle.IsAllocated)
            {
                _contextHandle.Free();
            }

            // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
            if (_pcaps != null)
            {
                foreach (var pcap in _pcaps)
                {
                    pcap.Dispose();
                }

                _pcaps = null!;
            }
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    #endregion
}

internal static unsafe class DispatchHelper
{
    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    public static void PacketCallback(byte* state, pcap_pkthdr* header, byte* data)
    {
        var context = (PcapDispatchContext)GCHandle.FromIntPtr((IntPtr)state).Target!;

        var packet = new Packet(header, data);

        context.Count += 1;
        context.Callback(context.Pcap, ref packet);
    }
}
