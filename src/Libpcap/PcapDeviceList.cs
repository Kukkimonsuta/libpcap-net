using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Net.NetworkInformation;
using Libpcap.Native;

namespace Libpcap;

public unsafe class PcapDeviceList : IReadOnlyList<PcapDevice>
{
    private readonly List<PcapDevice> _devices = new();

    internal PcapDeviceList([DisallowNull] pcap_if* devices)
    {
        if (devices == null)
            throw new ArgumentNullException(nameof(devices));

        // libpcap gives us only basic information, .net however
        // can contain some more, let's try to match them
        // together and use both
        var interfaces = NetworkInterface.GetAllNetworkInterfaces();

        // read data from native type, we read everything eagerly
        // so we can free the native memory while being able to
        // preserve information
        var device = devices;
        while (device != null)
        {
            _devices.Add(new PcapDevice(device, interfaces));
            device = device->next;
        }
    }

    public PcapDevice? FindActiveIPv4Device()
    {
        return this.Where(x => x.Flags.HasFlag(PcapDeviceFlags.Up) && x.Flags.HasFlag(PcapDeviceFlags.ConnectionStatusConnected))
            .Where(x => x.Type is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211)
            .OrderBy(x => x.IPv4Index == null)
            .ThenBy(x => x.IPv4Index)
            .FirstOrDefault();
    }

    public PcapDevice? FindActiveIPv6Device()
    {
        return this.Where(x => x.Flags.HasFlag(PcapDeviceFlags.Up) && x.Flags.HasFlag(PcapDeviceFlags.ConnectionStatusConnected))
            .Where(x => x.Type is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211)
            .OrderBy(x => x.IPv6Index == null)
            .ThenBy(x => x.IPv6Index)
            .FirstOrDefault();
    }

    #region IReadOnlyList

    IEnumerator IEnumerable.GetEnumerator() => ((IEnumerable)_devices).GetEnumerator();

    public IEnumerator<PcapDevice> GetEnumerator() => _devices.GetEnumerator();

    public int Count => _devices.Count;

    public PcapDevice this[int index] => _devices[index];

    #endregion
}
