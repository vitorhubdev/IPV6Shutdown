namespace IPV6Shutdown.Tests
{
    using IPV6Shutdown;
    using Xunit;

    public class AdapterProtectionTests
    {
        [Theory]
        [InlineData("CloudflareWARP", "Cloudflare WARP Interface Tunnel")]
        [InlineData("Tailscale", "Tailscale Tunnel")]
        [InlineData("WireGuard Tunnel: wg0", "WireGuard Tunnel")]
        [InlineData("Ethernet 3", "TAP-Windows Adapter V9")]
        [InlineData("NordLynx", "NordLynx Tunnel")]
        public void Known_vpn_adapters_are_protected(string name, string description)
        {
            Assert.NotNull(AdapterProtection.FindMatch(name, description));
        }

        [Theory]
        [InlineData("Ethernet", "Realtek PCIe GbE Family Controller")]
        [InlineData("Wi-Fi", "Intel(R) Wi-Fi 6 AX201 160MHz")]
        [InlineData("vEthernet (WSL)", "Hyper-V Virtual Ethernet Adapter")]
        public void Regular_adapters_are_not_protected(string name, string description)
        {
            Assert.Null(AdapterProtection.FindMatch(name, description));
        }

        [Fact]
        public void Custom_patterns_are_case_insensitive()
        {
            Assert.Equal("meuvpn", AdapterProtection.FindMatch("MeuVPN 1", "adapter", ["  MeuVPN "]));
        }

        [Theory]
        [InlineData("meuvpn", true)]
        [InlineData("", false)]
        [InlineData("a'b", false)]
        [InlineData("a\"b", false)]
        [InlineData("$(calc)", false)]
        public void Custom_pattern_validation_rejects_shell_metacharacters(string pattern, bool valid)
        {
            Assert.Equal(valid, AdapterProtection.IsValidCustomPattern(pattern));
        }
    }
}
