using Xunit;
using Xunit.Abstractions;

namespace Libpcap.Tests;

public class PcapFilterTests
{
    private readonly ITestOutputHelper _testOutputHelper;

    public PcapFilterTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public void Can_filter_file_pcap()
    {
        var reportedCount = 0;
        var actualCount = 0;

        using var pcap = Pcap.OpenFileRead("Resources/DHCPv6.cap");
        pcap.Filter = "udp";
        while (true)
        {
            var dispatched = pcap.Dispatch(1, (Pcap pcap, ref Packet packet) =>
            {
                Assert.NotNull(pcap);
                Assert.Equal(PcapDataLink.DLT_EN10MB, pcap.DataLink);
                Assert.Equal(packet.DeclaredLength, packet.CapturedLength);

                _testOutputHelper.WriteLine($"Packet Pcap={pcap.Name} DataLink={pcap.DataLink} Declared={packet.DeclaredLength} Captured={packet.CapturedLength}");

                actualCount += 1;
            });
            if (dispatched <= 0)
            {
                break;
            }

            reportedCount += dispatched;
        }

        Assert.Equal(6, reportedCount);
        Assert.Equal(reportedCount, actualCount);
    }

    [Fact]
    public void Can_filter_file_pcaps_using_dispatcher_before()
    {
        var reportedCount = 0;
        var actualCount = 0;

        using var dispatcher = new PcapDispatcher(
            (Pcap pcap, ref Packet packet) =>
            {
                Assert.NotNull(pcap);
                Assert.Equal(PcapDataLink.DLT_EN10MB, pcap.DataLink);
                Assert.Equal(packet.DeclaredLength, packet.CapturedLength);

                _testOutputHelper.WriteLine($"Packet Pcap={pcap.Name} DataLink={pcap.DataLink} Declared={packet.DeclaredLength} Captured={packet.CapturedLength}");

                actualCount += 1;

                // this verifies that pcaps are correctly rotated
                var fileReadPcap = pcap as FileReadPcap;
                Assert.NotNull(fileReadPcap);
                if (actualCount is 6)
                {
                    Assert.Equal("Resources/dhcp-auth.cap", fileReadPcap.Path);
                }
                else if (actualCount is 7 or 8)
                {
                    Assert.Equal("Resources/chargen-udp.pcap", fileReadPcap.Path);
                }
                else
                {
                    Assert.Equal("Resources/DHCPv6.cap", fileReadPcap.Path);
                }
            },
            rotateAfter: 5
        );

        dispatcher.Filter = "udp";

        dispatcher.OpenFile("Resources/DHCPv6.cap");
        dispatcher.OpenFile("Resources/dhcp-auth.cap");
        dispatcher.OpenFile("Resources/chargen-udp.pcap");

        while (true)
        {
            var dispatched = dispatcher.Dispatch(1111);
            if (dispatched <= 0)
            {
                break;
            }

            reportedCount += dispatched;
        }

        Assert.Equal(9, reportedCount);
        Assert.Equal(reportedCount, actualCount);
    }

    [Fact]
    public void Can_filter_file_pcaps_using_dispatcher_after()
    {
        var reportedCount = 0;
        var actualCount = 0;

        using var dispatcher = new PcapDispatcher(
            (Pcap pcap, ref Packet packet) =>
            {
                Assert.NotNull(pcap);
                Assert.Equal(PcapDataLink.DLT_EN10MB, pcap.DataLink);
                Assert.Equal(packet.DeclaredLength, packet.CapturedLength);

                _testOutputHelper.WriteLine($"Packet Pcap={pcap.Name} DataLink={pcap.DataLink} Declared={packet.DeclaredLength} Captured={packet.CapturedLength}");

                actualCount += 1;

                // this verifies that pcaps are correctly rotated
                var fileReadPcap = pcap as FileReadPcap;
                Assert.NotNull(fileReadPcap);
                if (actualCount is 6)
                {
                    Assert.Equal("Resources/dhcp-auth.cap", fileReadPcap.Path);
                }
                else if (actualCount is 7 or 8)
                {
                    Assert.Equal("Resources/chargen-udp.pcap", fileReadPcap.Path);
                }
                else
                {
                    Assert.Equal("Resources/DHCPv6.cap", fileReadPcap.Path);
                }
            },
            rotateAfter: 5
        );

        dispatcher.OpenFile("Resources/DHCPv6.cap");
        dispatcher.OpenFile("Resources/dhcp-auth.cap");
        dispatcher.OpenFile("Resources/chargen-udp.pcap");

        dispatcher.Filter = "udp";

        while (true)
        {
            var dispatched = dispatcher.Dispatch(1111);
            if (dispatched <= 0)
            {
                break;
            }

            reportedCount += dispatched;
        }

        Assert.Equal(9, reportedCount);
        Assert.Equal(reportedCount, actualCount);
    }
}
