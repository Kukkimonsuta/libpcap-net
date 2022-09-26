using Xunit;
using Xunit.Abstractions;

namespace Libpcap.Tests;

public class FileWritePcapTests
{
    private readonly ITestOutputHelper _testOutputHelper;

    public FileWritePcapTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public void Can_write_pcap_file()
    {
        // write the file
        {
            var reportedCount = 0;
            var actualCount = 0;

            using var dump = Pcap.OpenFileWrite("Resources/DHCPv6-copy.pcap", PcapDataLink.DLT_EN10MB, 65535);

            using var pcap = Pcap.OpenFileRead("Resources/DHCPv6.cap");
            while (true)
            {
                var dispatched = pcap.Dispatch(
                    1, (Pcap pcap, ref Packet packet) =>
                    {
                        Assert.NotNull(pcap);
                        Assert.Equal(PcapDataLink.DLT_EN10MB, pcap.DataLink);
                        Assert.Equal(packet.DeclaredLength, packet.CapturedLength);

                        _testOutputHelper.WriteLine($"Packet Pcap={pcap.Name} DataLink={pcap.DataLink} Declared={packet.DeclaredLength} Captured={packet.CapturedLength}");
                        // ReSharper disable once AccessToDisposedClosure
                        dump.Write(ref packet);

                        actualCount += 1;
                    }
                );
                if (dispatched <= 0)
                {
                    break;
                }

                reportedCount += dispatched;
            }

            Assert.Equal(12, reportedCount);
            Assert.Equal(reportedCount, actualCount);
        }

        // verify
        {
            var reportedCount = 0;
            var actualCount = 0;

            using var pcap = Pcap.OpenFileRead("Resources/DHCPv6-copy.pcap");
            while (true)
            {
                var dispatched = pcap.Dispatch(
                    1, (Pcap pcap, ref Packet packet) =>
                    {
                        Assert.NotNull(pcap);
                        Assert.Equal(PcapDataLink.DLT_EN10MB, pcap.DataLink);
                        Assert.Equal(packet.DeclaredLength, packet.CapturedLength);

                        _testOutputHelper.WriteLine($"Packet Pcap={pcap.Name} DataLink={pcap.DataLink} Declared={packet.DeclaredLength} Captured={packet.CapturedLength}");

                        actualCount += 1;
                    }
                );
                if (dispatched <= 0)
                {
                    break;
                }

                reportedCount += dispatched;
            }

            Assert.Equal(12, reportedCount);
            Assert.Equal(reportedCount, actualCount);
        }
    }
}
