using Libpcap.Native;
// ReSharper disable InconsistentNaming

namespace Libpcap;

public enum PcapActivateResult
{
    /// <summary>
    /// Pcap activation was successful.
    /// </summary>
    Success = 0,

    /// <summary>
    /// Promiscuous mode was requested, but the capture source doesn't support promiscuous mode.
    /// </summary>
    PCAP_WARNING_PROMISC_NOTSUP = LibpcapNative.PCAP_WARNING_PROMISC_NOTSUP,

    /// <summary>
    /// The time stamp type specified in a previous pcap_set_tstamp_type call isn't supported by the capture source (the time stamp type is left as the default),
    /// </summary>
    PCAP_WARNING_TSTAMP_TYPE_NOTSUP = LibpcapNative.PCAP_WARNING_TSTAMP_TYPE_NOTSUP,

    /// <summary>
    /// Another warning condition occurred; pcap_geterr or pcap_perror may be called with p as an argument to fetch or display a message describing the warning condition.
    /// </summary>
    PCAP_WARNING = LibpcapNative.PCAP_WARNING,

    /// <summary>
    /// The handle has already been activated.
    /// </summary>
    PCAP_ERROR_ACTIVATED = LibpcapNative.PCAP_ERROR_ACTIVATED,

    /// <summary>
    /// The capture source specified when the handle was created doesn't exist.
    /// </summary>
    PCAP_ERROR_NO_SUCH_DEVICE = LibpcapNative.PCAP_ERROR_NO_SUCH_DEVICE,

    /// <summary>
    /// The process doesn't have permission to open the capture source.
    /// </summary>
    PCAP_ERROR_PERM_DENIED = LibpcapNative.PCAP_ERROR_PERM_DENIED,

    /// <summary>
    /// The process has permission to open the capture source but doesn't have permission to put it into promiscuous mode.
    /// </summary>
    PCAP_ERROR_PROMISC_PERM_DENIED = LibpcapNative.PCAP_ERROR_PROMISC_PERM_DENIED,

    /// <summary>
    /// Monitor mode was specified but the capture source doesn't support monitor mode.
    /// </summary>
    PCAP_ERROR_RFMON_NOTSUP = LibpcapNative.PCAP_ERROR_RFMON_NOTSUP,

    /// <summary>
    /// The capture source device is not up.
    /// </summary>
    PCAP_ERROR_IFACE_NOT_UP = LibpcapNative.PCAP_ERROR_IFACE_NOT_UP,

    /// <summary>
    /// Another error occurred. pcap_geterr() or pcap_perror() may be called with p as an argument to fetch or display a message describing the error.
    /// </summary>
    PCAP_ERROR = LibpcapNative.PCAP_ERROR,
}
