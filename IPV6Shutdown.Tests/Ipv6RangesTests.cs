namespace IPV6Shutdown.Tests
{
    using System.Net;
    using IPV6Shutdown;
    using Xunit;

    public class Ipv6RangesTests
    {
        private static bool Covers(string ranges, string address)
        {
            UInt128 value = Ipv6Ranges.ParseCidr(address + "/128").Start;
            foreach (string range in ranges.Split(','))
            {
                string[] ends = range.Split('-');
                UInt128 start = Ipv6Ranges.ParseCidr(ends[0] + "/128").Start;
                UInt128 end = Ipv6Ranges.ParseCidr(ends[^1] + "/128").Start;
                if (value >= start && value <= end)
                    return true;
            }
            return false;
        }

        [Theory]
        [InlineData("fd7a:115c:a1e0::1")]
        [InlineData("fd7a:115c:a1e0:ffff:ffff:ffff:ffff:ffff")]
        [InlineData("fd01:db8:1111::2")]
        [InlineData("fd01:db8:1111::3")]
        [InlineData("::1")]
        [InlineData("fe80::1")]
        public void Default_exclusions_are_never_blocked(string address)
        {
            string ranges = Ipv6Ranges.BuildBlockedRanges(Ipv6Ranges.DefaultExclusions);
            Assert.False(Covers(ranges, address));
        }

        [Theory]
        [InlineData("2606:4700:4700::1111")]
        [InlineData("2001:db8::1")]
        [InlineData("::")]
        [InlineData("fd7a:115c:a1df:ffff:ffff:ffff:ffff:ffff")]
        [InlineData("fd7a:115c:a1e1::")]
        [InlineData("fd01:db8:1112::1")]
        [InlineData("fec0::1")]
        [InlineData("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")]
        public void Everything_else_is_blocked(string address)
        {
            string ranges = Ipv6Ranges.BuildBlockedRanges(Ipv6Ranges.DefaultExclusions);
            Assert.True(Covers(ranges, address));
        }

        [Fact]
        public void Overlapping_exclusions_are_merged()
        {
            string ranges = Ipv6Ranges.BuildBlockedRanges(["fe80::/10", "fe80::/64", "::1/128"]);
            Assert.False(Covers(ranges, "fe80::1"));
            Assert.False(Covers(ranges, "febf::1"));
            Assert.True(Covers(ranges, "fec0::1"));
        }

        [Fact]
        public void Single_address_gap_is_emitted_without_a_range()
        {
            // ::1 excluído => o primeiro trecho bloqueado é só "::" (um endereço)
            string ranges = Ipv6Ranges.BuildBlockedRanges(["::1/128"]);
            Assert.StartsWith("::,", ranges);
        }

        [Fact]
        public void No_exclusions_blocks_whole_space()
        {
            Assert.Equal("::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Ipv6Ranges.BuildBlockedRanges([]));
        }

        [Fact]
        public void Exclusion_at_the_end_of_the_space_is_handled()
        {
            string ranges = Ipv6Ranges.BuildBlockedRanges(["ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"]);
            Assert.True(Covers(ranges, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"));
            Assert.False(Covers(ranges, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
        }

        [Theory]
        [InlineData("nope")]
        [InlineData("1.2.3.4/24")]
        [InlineData("fe80::/129")]
        public void Invalid_prefix_throws(string cidr)
        {
            Assert.Throws<FormatException>(() => Ipv6Ranges.ParseCidr(cidr));
        }
    }
}
