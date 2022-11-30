# libpcap-net [![Build](https://github.com/Kukkimonsuta/libpcap-net/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/Kukkimonsuta/libpcap-net/actions/workflows/build.yml) [![Publish](https://github.com/Kukkimonsuta/libpcap-net/actions/workflows/publish.yml/badge.svg)](https://github.com/Kukkimonsuta/libpcap-net/actions/workflows/publish.yml) [![NuGet Badge](https://img.shields.io/nuget/v/libpcap?logo=nuget)](https://www.nuget.org/packages/libpcap/)

Libpcap/Npcap wrapper for .NET.

## Dependencies

For linux/mac libpcap ( https://www.tcpdump.org/ ), for windows npcap ( https://npcap.com/ ). These libraries are not shipped within the package, they are expected to be present on the system.

## Usage - listen to network

```csharp
// get all available devices
var devices = Pcap.ListDevices();

// select desired device
var device = devices.First();

// open and activate
using var pcap = Pcap.OpenDevice(device);
pcap.Activate();
```

## Usage - read from file

```csharp
using var pcap = Pcap.OpenFileRead("Resources/DHCPv6.cap");
```

## Usage - process packets

```csharp
pcap.Dispatch(100, (Pcap pcap, ref Packet packet) =>
{
    // read packet.Timestamp
    // read packet.Data
});
```

## Usage - process packets from multiple devices

Note that this way is preferred even with single source device, as every call to `Pcap.Dispatch` allocates GCHandle whereas `PcapDispatcher.Dispatch` doesn't.

```csharp
using var dispatcher = new PcapDispatcher(
    (Pcap pcap, ref Packet packet) =>
    {
        // read packet.Timestamp
        // read packet.Data
    }
);

dispatcher.OpenDevice(device1);
dispatcher.OpenDevice(device2);
dispatcher.OpenFile("Resources/DHCPv6.cap");
dispatcher.OpenFile("Resources/dhcp-auth.cap");

dispatcher.Dispatch(100);
```

## Usage - recoding to file

```csharp
using var dump = Pcap.OpenFileWrite("Resources/DHCPv6-copy.pcap", PcapDataLink.DLT_EN10MB, 65535);

pcap.Dispatch(100, (Pcap pcap, ref Packet packet) =>
{
    dump.Write(ref packet);
});

```
