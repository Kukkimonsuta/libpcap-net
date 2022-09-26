using System.Diagnostics.CodeAnalysis;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Libpcap.Native;

namespace Libpcap;

public unsafe class PcapDevice
{
    private readonly NetworkInterface? _networkInterface;

    internal PcapDevice([DisallowNull] pcap_if* device, NetworkInterface[] networkInterfaces)
    {
        if (device == null)
            throw new ArgumentNullException(nameof(device));

        Name = Marshal.PtrToStringUTF8((IntPtr)device->name) ?? "<no name>";
        if (device->description != null)
        {
            Description = Marshal.PtrToStringUTF8((IntPtr)device->description);
        }
        Flags = (PcapDeviceFlags)device->flags;
        Addresses = new PcapDeviceAddressList(device->addresses);

        _networkInterface = networkInterfaces.Where(this.Matches).FirstOrDefault();
    }

    public string Name { get; }
    public string? Description { get; }
    public PcapDeviceFlags Flags { get; }

    public PcapDeviceAddressList Addresses { get; }

    public NetworkInterfaceType? Type => _networkInterface?.NetworkInterfaceType;

    public int? IPv4Index => _networkInterface?.GetIPProperties().GetIPv4Properties().Index;

    public int? IPv6Index => _networkInterface?.GetIPProperties().GetIPv6Properties().Index;
}

public static class PcapDeviceExtensions
{
    private const string NetworkPacketFilterDevicePrefix = "\\Device\\NPF_";

    public static bool Matches(this PcapDevice pcapDevice, NetworkInterface networkInterface)
    {
        if (pcapDevice.Name.StartsWith(NetworkPacketFilterDevicePrefix))
        {
            return pcapDevice.Name.AsSpan(NetworkPacketFilterDevicePrefix.Length).Equals(networkInterface.Id.AsSpan(), StringComparison.OrdinalIgnoreCase);
        }

        return pcapDevice.Name == networkInterface.Id;
    }
}
