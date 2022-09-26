using System.Collections;
using Libpcap.Native;

namespace Libpcap;

public unsafe class PcapDeviceAddressList : IReadOnlyList<PcapDeviceAddress>
{
    private readonly List<PcapDeviceAddress> _deviceAddresses = new();

    internal PcapDeviceAddressList(pcap_addr* addresses)
    {
        // populate managed wrappers.. ideally this would be lazy
        var address = addresses;
        while (address != null)
        {
            _deviceAddresses.Add(new PcapDeviceAddress(address));
            address = address->next;
        }
    }

    #region IReadOnlyList

    IEnumerator IEnumerable.GetEnumerator() => ((IEnumerable)_deviceAddresses).GetEnumerator();

    public IEnumerator<PcapDeviceAddress> GetEnumerator() => _deviceAddresses.GetEnumerator();

    public int Count => _deviceAddresses.Count;

    public PcapDeviceAddress this[int index] => _deviceAddresses[index];

    #endregion
}
