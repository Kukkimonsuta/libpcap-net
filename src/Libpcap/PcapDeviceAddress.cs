using System.Diagnostics.CodeAnalysis;
using Libpcap.Native;

namespace Libpcap;

public unsafe class PcapDeviceAddress
{
    internal PcapDeviceAddress([DisallowNull] pcap_addr* address)
    {
        if (address == null)
            throw new ArgumentNullException(nameof(address));

        Address = PcapAddress.FromSockAddr(address->addr);
        if (address->netmask != null)
        {
            Mask = PcapAddress.FromSockAddr(address->netmask);
        }
        if (address->broadaddr != null)
        {
            Broadcast = PcapAddress.FromSockAddr(address->broadaddr);
        }
        if (address->dstaddr != null)
        {
            Destination = PcapAddress.FromSockAddr(address->dstaddr);
        }
    }

    public PcapAddress Address { get; }
    public PcapAddress? Mask { get; }

    public PcapAddress? Broadcast { get; set; }

    public PcapAddress? Destination { get; set; }
}
