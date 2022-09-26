using Libpcap.Native;

namespace Libpcap;

public enum PcapDataLink
{
    DLT_NULL = LibpcapNative.DLT_NULL,
    DLT_EN10MB = LibpcapNative.DLT_EN10MB,
    DLT_EN3MB = LibpcapNative.DLT_EN3MB,
    DLT_AX25 = LibpcapNative.DLT_AX25,
    DLT_PRONET = LibpcapNative.DLT_PRONET,
    DLT_CHAOS = LibpcapNative.DLT_CHAOS,
    DLT_IEEE802 = LibpcapNative.DLT_IEEE802,
    DLT_ARCNET = LibpcapNative.DLT_ARCNET,
    DLT_SLIP = LibpcapNative.DLT_SLIP,
    DLT_PPP = LibpcapNative.DLT_PPP,
    DLT_FDDI = LibpcapNative.DLT_FDDI,
    DLT_ATM_RFC1483 = LibpcapNative.DLT_ATM_RFC1483,
    DLT_RAW = LibpcapNative.DLT_RAW,
    DLT_SLIP_BSDOS = LibpcapNative.DLT_SLIP_BSDOS,
    DLT_PPP_BSDOS = LibpcapNative.DLT_PPP_BSDOS,
    DLT_ATM_CLIP = LibpcapNative.DLT_ATM_CLIP,
    DLT_REDBACK_SMARTEDGE = LibpcapNative.DLT_REDBACK_SMARTEDGE,
    DLT_PPP_SERIAL = LibpcapNative.DLT_PPP_SERIAL,
    DLT_PPP_ETHER = LibpcapNative.DLT_PPP_ETHER,
    DLT_SYMANTEC_FIREWALL = LibpcapNative.DLT_SYMANTEC_FIREWALL,
    DLT_MATCHING_MIN = LibpcapNative.DLT_MATCHING_MIN,
    DLT_C_HDLC = LibpcapNative.DLT_C_HDLC,
    DLT_CHDLC = LibpcapNative.DLT_CHDLC,
    DLT_IEEE802_11 = LibpcapNative.DLT_IEEE802_11,
    DLT_FRELAY = LibpcapNative.DLT_FRELAY,
    DLT_LOOP = LibpcapNative.DLT_LOOP,
    DLT_ENC = LibpcapNative.DLT_ENC,
    DLT_LINUX_SLL = LibpcapNative.DLT_LINUX_SLL,
    DLT_LTALK = LibpcapNative.DLT_LTALK,
    DLT_ECONET = LibpcapNative.DLT_ECONET,
    DLT_IPFILTER = LibpcapNative.DLT_IPFILTER,
    DLT_PFLOG = LibpcapNative.DLT_PFLOG,
    DLT_CISCO_IOS = LibpcapNative.DLT_CISCO_IOS,
    DLT_PRISM_HEADER = LibpcapNative.DLT_PRISM_HEADER,
    DLT_AIRONET_HEADER = LibpcapNative.DLT_AIRONET_HEADER,
    DLT_HHDLC = LibpcapNative.DLT_HHDLC,
    DLT_IP_OVER_FC = LibpcapNative.DLT_IP_OVER_FC,
    DLT_SUNATM = LibpcapNative.DLT_SUNATM,
    DLT_RIO = LibpcapNative.DLT_RIO,
    DLT_PCI_EXP = LibpcapNative.DLT_PCI_EXP,
    DLT_AURORA = LibpcapNative.DLT_AURORA,
    DLT_IEEE802_11_RADIO = LibpcapNative.DLT_IEEE802_11_RADIO,
    DLT_TZSP = LibpcapNative.DLT_TZSP,
    DLT_ARCNET_LINUX = LibpcapNative.DLT_ARCNET_LINUX,
    DLT_JUNIPER_MLPPP = LibpcapNative.DLT_JUNIPER_MLPPP,
    DLT_JUNIPER_MLFR = LibpcapNative.DLT_JUNIPER_MLFR,
    DLT_JUNIPER_ES = LibpcapNative.DLT_JUNIPER_ES,
    DLT_JUNIPER_GGSN = LibpcapNative.DLT_JUNIPER_GGSN,
    DLT_JUNIPER_MFR = LibpcapNative.DLT_JUNIPER_MFR,
    DLT_JUNIPER_ATM2 = LibpcapNative.DLT_JUNIPER_ATM2,
    DLT_JUNIPER_SERVICES = LibpcapNative.DLT_JUNIPER_SERVICES,
    DLT_JUNIPER_ATM1 = LibpcapNative.DLT_JUNIPER_ATM1,
    DLT_APPLE_IP_OVER_IEEE1394 = LibpcapNative.DLT_APPLE_IP_OVER_IEEE1394,
    DLT_MTP2_WITH_PHDR = LibpcapNative.DLT_MTP2_WITH_PHDR,
    DLT_MTP2 = LibpcapNative.DLT_MTP2,
    DLT_MTP3 = LibpcapNative.DLT_MTP3,
    DLT_SCCP = LibpcapNative.DLT_SCCP,
    DLT_DOCSIS = LibpcapNative.DLT_DOCSIS,
    DLT_LINUX_IRDA = LibpcapNative.DLT_LINUX_IRDA,
    DLT_IBM_SP = LibpcapNative.DLT_IBM_SP,
    DLT_IBM_SN = LibpcapNative.DLT_IBM_SN,
    DLT_USER0 = LibpcapNative.DLT_USER0,
    DLT_USER1 = LibpcapNative.DLT_USER1,
    DLT_USER2 = LibpcapNative.DLT_USER2,
    DLT_USER3 = LibpcapNative.DLT_USER3,
    DLT_USER4 = LibpcapNative.DLT_USER4,
    DLT_USER5 = LibpcapNative.DLT_USER5,
    DLT_USER6 = LibpcapNative.DLT_USER6,
    DLT_USER7 = LibpcapNative.DLT_USER7,
    DLT_USER8 = LibpcapNative.DLT_USER8,
    DLT_USER9 = LibpcapNative.DLT_USER9,
    DLT_USER10 = LibpcapNative.DLT_USER10,
    DLT_USER11 = LibpcapNative.DLT_USER11,
    DLT_USER12 = LibpcapNative.DLT_USER12,
    DLT_USER13 = LibpcapNative.DLT_USER13,
    DLT_USER14 = LibpcapNative.DLT_USER14,
    DLT_USER15 = LibpcapNative.DLT_USER15,
    DLT_IEEE802_11_RADIO_AVS = LibpcapNative.DLT_IEEE802_11_RADIO_AVS,
    DLT_JUNIPER_MONITOR = LibpcapNative.DLT_JUNIPER_MONITOR,
    DLT_BACNET_MS_TP = LibpcapNative.DLT_BACNET_MS_TP,
    DLT_PPP_PPPD = LibpcapNative.DLT_PPP_PPPD,
    DLT_PPP_WITH_DIRECTION = LibpcapNative.DLT_PPP_WITH_DIRECTION,
    DLT_LINUX_PPP_WITHDIRECTION = LibpcapNative.DLT_LINUX_PPP_WITHDIRECTION,
    DLT_JUNIPER_PPPOE = LibpcapNative.DLT_JUNIPER_PPPOE,
    DLT_JUNIPER_PPPOE_ATM = LibpcapNative.DLT_JUNIPER_PPPOE_ATM,
    DLT_GPRS_LLC = LibpcapNative.DLT_GPRS_LLC,
    DLT_GPF_T = LibpcapNative.DLT_GPF_T,
    DLT_GPF_F = LibpcapNative.DLT_GPF_F,
    DLT_GCOM_T1E1 = LibpcapNative.DLT_GCOM_T1E1,
    DLT_GCOM_SERIAL = LibpcapNative.DLT_GCOM_SERIAL,
    DLT_JUNIPER_PIC_PEER = LibpcapNative.DLT_JUNIPER_PIC_PEER,
    DLT_ERF_ETH = LibpcapNative.DLT_ERF_ETH,
    DLT_ERF_POS = LibpcapNative.DLT_ERF_POS,
    DLT_LINUX_LAPD = LibpcapNative.DLT_LINUX_LAPD,
    DLT_JUNIPER_ETHER = LibpcapNative.DLT_JUNIPER_ETHER,
    DLT_JUNIPER_PPP = LibpcapNative.DLT_JUNIPER_PPP,
    DLT_JUNIPER_FRELAY = LibpcapNative.DLT_JUNIPER_FRELAY,
    DLT_JUNIPER_CHDLC = LibpcapNative.DLT_JUNIPER_CHDLC,
    DLT_MFR = LibpcapNative.DLT_MFR,
    DLT_JUNIPER_VP = LibpcapNative.DLT_JUNIPER_VP,
    DLT_A429 = LibpcapNative.DLT_A429,
    DLT_A653_ICM = LibpcapNative.DLT_A653_ICM,
    DLT_USB_FREEBSD = LibpcapNative.DLT_USB_FREEBSD,
    DLT_USB = LibpcapNative.DLT_USB,
    DLT_BLUETOOTH_HCI_H4 = LibpcapNative.DLT_BLUETOOTH_HCI_H4,
    DLT_IEEE802_16_MAC_CPS = LibpcapNative.DLT_IEEE802_16_MAC_CPS,
    DLT_USB_LINUX = LibpcapNative.DLT_USB_LINUX,
    DLT_CAN20B = LibpcapNative.DLT_CAN20B,
    DLT_IEEE802_15_4_LINUX = LibpcapNative.DLT_IEEE802_15_4_LINUX,
    DLT_PPI = LibpcapNative.DLT_PPI,
    DLT_IEEE802_16_MAC_CPS_RADIO = LibpcapNative.DLT_IEEE802_16_MAC_CPS_RADIO,
    DLT_JUNIPER_ISM = LibpcapNative.DLT_JUNIPER_ISM,
    DLT_IEEE802_15_4_WITHFCS = LibpcapNative.DLT_IEEE802_15_4_WITHFCS,
    DLT_IEEE802_15_4 = LibpcapNative.DLT_IEEE802_15_4,
    DLT_SITA = LibpcapNative.DLT_SITA,
    DLT_ERF = LibpcapNative.DLT_ERF,
    DLT_RAIF1 = LibpcapNative.DLT_RAIF1,
    DLT_IPMB_KONTRON = LibpcapNative.DLT_IPMB_KONTRON,
    DLT_JUNIPER_ST = LibpcapNative.DLT_JUNIPER_ST,
    DLT_BLUETOOTH_HCI_H4_WITH_PHDR = LibpcapNative.DLT_BLUETOOTH_HCI_H4_WITH_PHDR,
    DLT_AX25_KISS = LibpcapNative.DLT_AX25_KISS,
    DLT_LAPD = LibpcapNative.DLT_LAPD,
    DLT_PPP_WITH_DIR = LibpcapNative.DLT_PPP_WITH_DIR,
    DLT_C_HDLC_WITH_DIR = LibpcapNative.DLT_C_HDLC_WITH_DIR,
    DLT_FRELAY_WITH_DIR = LibpcapNative.DLT_FRELAY_WITH_DIR,
    DLT_LAPB_WITH_DIR = LibpcapNative.DLT_LAPB_WITH_DIR,
    DLT_IPMB_LINUX = LibpcapNative.DLT_IPMB_LINUX,
    DLT_FLEXRAY = LibpcapNative.DLT_FLEXRAY,
    DLT_MOST = LibpcapNative.DLT_MOST,
    DLT_LIN = LibpcapNative.DLT_LIN,
    DLT_X2E_SERIAL = LibpcapNative.DLT_X2E_SERIAL,
    DLT_X2E_XORAYA = LibpcapNative.DLT_X2E_XORAYA,
    DLT_IEEE802_15_4_NONASK_PHY = LibpcapNative.DLT_IEEE802_15_4_NONASK_PHY,
    DLT_LINUX_EVDEV = LibpcapNative.DLT_LINUX_EVDEV,
    DLT_GSMTAP_UM = LibpcapNative.DLT_GSMTAP_UM,
    DLT_GSMTAP_ABIS = LibpcapNative.DLT_GSMTAP_ABIS,
    DLT_MPLS = LibpcapNative.DLT_MPLS,
    DLT_USB_LINUX_MMAPPED = LibpcapNative.DLT_USB_LINUX_MMAPPED,
    DLT_DECT = LibpcapNative.DLT_DECT,
    DLT_AOS = LibpcapNative.DLT_AOS,
    DLT_WIHART = LibpcapNative.DLT_WIHART,
    DLT_FC_2 = LibpcapNative.DLT_FC_2,
    DLT_FC_2_WITH_FRAME_DELIMS = LibpcapNative.DLT_FC_2_WITH_FRAME_DELIMS,
    DLT_IPNET = LibpcapNative.DLT_IPNET,
    DLT_CAN_SOCKETCAN = LibpcapNative.DLT_CAN_SOCKETCAN,
    DLT_IPV4 = LibpcapNative.DLT_IPV4,
    DLT_IPV6 = LibpcapNative.DLT_IPV6,
    DLT_IEEE802_15_4_NOFCS = LibpcapNative.DLT_IEEE802_15_4_NOFCS,
    DLT_DBUS = LibpcapNative.DLT_DBUS,
    DLT_JUNIPER_VS = LibpcapNative.DLT_JUNIPER_VS,
    DLT_JUNIPER_SRX_E2E = LibpcapNative.DLT_JUNIPER_SRX_E2E,
    DLT_JUNIPER_FIBRECHANNEL = LibpcapNative.DLT_JUNIPER_FIBRECHANNEL,
    DLT_DVB_CI = LibpcapNative.DLT_DVB_CI,
    DLT_MUX27010 = LibpcapNative.DLT_MUX27010,
    DLT_STANAG_5066_D_PDU = LibpcapNative.DLT_STANAG_5066_D_PDU,
    DLT_JUNIPER_ATM_CEMIC = LibpcapNative.DLT_JUNIPER_ATM_CEMIC,
    DLT_NFLOG = LibpcapNative.DLT_NFLOG,
    DLT_NETANALYZER = LibpcapNative.DLT_NETANALYZER,
    DLT_NETANALYZER_TRANSPARENT = LibpcapNative.DLT_NETANALYZER_TRANSPARENT,
    DLT_IPOIB = LibpcapNative.DLT_IPOIB,
    DLT_MPEG_2_TS = LibpcapNative.DLT_MPEG_2_TS,
    DLT_NG40 = LibpcapNative.DLT_NG40,
    DLT_NFC_LLCP = LibpcapNative.DLT_NFC_LLCP,
    DLT_PFSYNC = LibpcapNative.DLT_PFSYNC,
    DLT_INFINIBAND = LibpcapNative.DLT_INFINIBAND,
    DLT_SCTP = LibpcapNative.DLT_SCTP,
    DLT_USBPCAP = LibpcapNative.DLT_USBPCAP,
    DLT_RTAC_SERIAL = LibpcapNative.DLT_RTAC_SERIAL,
    DLT_BLUETOOTH_LE_LL = LibpcapNative.DLT_BLUETOOTH_LE_LL,
    DLT_WIRESHARK_UPPER_PDU = LibpcapNative.DLT_WIRESHARK_UPPER_PDU,
    DLT_NETLINK = LibpcapNative.DLT_NETLINK,
    DLT_BLUETOOTH_LINUX_MONITOR = LibpcapNative.DLT_BLUETOOTH_LINUX_MONITOR,
    DLT_BLUETOOTH_BREDR_BB = LibpcapNative.DLT_BLUETOOTH_BREDR_BB,
    DLT_BLUETOOTH_LE_LL_WITH_PHDR = LibpcapNative.DLT_BLUETOOTH_LE_LL_WITH_PHDR,
    DLT_PROFIBUS_DL = LibpcapNative.DLT_PROFIBUS_DL,
    DLT_PKTAP = LibpcapNative.DLT_PKTAP,
    DLT_EPON = LibpcapNative.DLT_EPON,
    DLT_IPMI_HPM_2 = LibpcapNative.DLT_IPMI_HPM_2,
    DLT_ZWAVE_R1_R2 = LibpcapNative.DLT_ZWAVE_R1_R2,
    DLT_ZWAVE_R3 = LibpcapNative.DLT_ZWAVE_R3,
    DLT_WATTSTOPPER_DLM = LibpcapNative.DLT_WATTSTOPPER_DLM,
    DLT_ISO_14443 = LibpcapNative.DLT_ISO_14443,
    DLT_RDS = LibpcapNative.DLT_RDS,
    DLT_USB_DARWIN = LibpcapNative.DLT_USB_DARWIN,
    DLT_OPENFLOW = LibpcapNative.DLT_OPENFLOW,
    DLT_SDLC = LibpcapNative.DLT_SDLC,
    DLT_TI_LLN_SNIFFER = LibpcapNative.DLT_TI_LLN_SNIFFER,
    DLT_LORATAP = LibpcapNative.DLT_LORATAP,
    DLT_VSOCK = LibpcapNative.DLT_VSOCK,
    DLT_NORDIC_BLE = LibpcapNative.DLT_NORDIC_BLE,
    DLT_DOCSIS31_XRA31 = LibpcapNative.DLT_DOCSIS31_XRA31,
    DLT_ETHERNET_MPACKET = LibpcapNative.DLT_ETHERNET_MPACKET,
    DLT_DISPLAYPORT_AUX = LibpcapNative.DLT_DISPLAYPORT_AUX,
    DLT_LINUX_SLL2 = LibpcapNative.DLT_LINUX_SLL2,
    DLT_SERCOS_MONITOR = LibpcapNative.DLT_SERCOS_MONITOR,
    DLT_OPENVIZSLA = LibpcapNative.DLT_OPENVIZSLA,
    DLT_EBHSCR = LibpcapNative.DLT_EBHSCR,
    DLT_VPP_DISPATCH = LibpcapNative.DLT_VPP_DISPATCH,
    DLT_DSA_TAG_BRCM = LibpcapNative.DLT_DSA_TAG_BRCM,
    DLT_DSA_TAG_BRCM_PREPEND = LibpcapNative.DLT_DSA_TAG_BRCM_PREPEND,
    DLT_IEEE802_15_4_TAP = LibpcapNative.DLT_IEEE802_15_4_TAP,
    DLT_DSA_TAG_DSA = LibpcapNative.DLT_DSA_TAG_DSA,
    DLT_DSA_TAG_EDSA = LibpcapNative.DLT_DSA_TAG_EDSA,
    DLT_ELEE = LibpcapNative.DLT_ELEE,
    DLT_Z_WAVE_SERIAL = LibpcapNative.DLT_Z_WAVE_SERIAL,
    DLT_USB_2_0 = LibpcapNative.DLT_USB_2_0,
    DLT_ATSC_ALP = LibpcapNative.DLT_ATSC_ALP,
    DLT_MATCHING_MAX = LibpcapNative.DLT_MATCHING_MAX,
    DLT_CLASS_NETBSD_RAWAF = LibpcapNative.DLT_CLASS_NETBSD_RAWAF,
}
