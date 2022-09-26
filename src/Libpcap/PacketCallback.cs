namespace Libpcap;

public delegate void PacketCallback(Pcap pcap, ref Packet packet);
