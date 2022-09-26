using Libpcap.Native;

namespace Libpcap;

[Flags]
public enum PcapDeviceFlags : uint
{
    Loopback = LibpcapNative.PCAP_IF_LOOPBACK,
    Up = LibpcapNative.PCAP_IF_UP,
    Running = LibpcapNative.PCAP_IF_RUNNING,
    Wireless = LibpcapNative.PCAP_IF_WIRELESS,
    ConnectionStatus = LibpcapNative.PCAP_IF_CONNECTION_STATUS,
    ConnectionStatusUnknown = LibpcapNative.PCAP_IF_CONNECTION_STATUS_UNKNOWN,
    ConnectionStatusConnected = LibpcapNative.PCAP_IF_CONNECTION_STATUS_CONNECTED,
    ConnectionStatusDisconnected = LibpcapNative.PCAP_IF_CONNECTION_STATUS_DISCONNECTED,
    ConnectionStatusNotApplicable = LibpcapNative.PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE,
}
