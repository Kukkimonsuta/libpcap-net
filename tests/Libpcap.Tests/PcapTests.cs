using Xunit;
using Xunit.Abstractions;

namespace Libpcap.Tests;

public class PcapTests
{
    private readonly ITestOutputHelper _testOutputHelper;

    public PcapTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public void Can_find_devices()
    {
        var devices = Pcap.ListDevices();
        Assert.NotNull(devices);

        foreach (var device in devices.Where(x => x.Flags.HasFlag(PcapDeviceFlags.Up) && x.Flags.HasFlag(PcapDeviceFlags.ConnectionStatusConnected)).OrderBy(x => x.IPv4Index == null).ThenBy(x => x.IPv4Index))
        {
            _testOutputHelper.WriteLine($"Device {device.Name}");
            _testOutputHelper.WriteLine($" - Description: {device.Description}");
            _testOutputHelper.WriteLine($" - Flags: {device.Flags}");
            _testOutputHelper.WriteLine($" - IP v4 index: {device.IPv4Index?.ToString() ?? "null"}");
            _testOutputHelper.WriteLine($" - IP v6 index: {device.IPv6Index?.ToString() ?? "null"}");

            foreach (var address in device.Addresses)
            {
                var addressString = default(string);
                if (address.Address is PcapIPAddress pcapIpAddress)
                {
                    addressString = $" {pcapIpAddress.Address}";
                }

                _testOutputHelper.WriteLine($" - Address {address.Address.Family}{addressString}");
            }

            _testOutputHelper.WriteLine("");
        }

        Assert.NotEmpty(devices);
    }

    [Fact(Skip = "In CI there won't be permissions to activate devices.")]
    public void Can_activate_loopback()
    {
        var devices = Pcap.ListDevices();
        Assert.NotNull(devices);

        var device = devices.First(x => x.Flags.HasFlag(PcapDeviceFlags.Loopback));

        using var pcap = Pcap.OpenDevice(device);
        Assert.NotNull(pcap);

        pcap.Activate();
    }
}
