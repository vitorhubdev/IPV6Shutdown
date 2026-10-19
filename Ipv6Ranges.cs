using System.Net;

namespace IPV6Shutdown
{
    /// <summary>Builds the firewall RemoteAddress list "all IPv6 except these prefixes" (unit-testable).</summary>
    internal static class Ipv6Ranges
    {
        /// <summary>
        /// Prefixes que o bloqueio de firewall nunca deve atingir:
        /// loopback, link-local, ULA do Tailscale e ULA do Cloudflare WARP (DNS local fd01:db8:1111::2/3).
        /// </summary>
        internal static readonly string[] DefaultExclusions =
        [
            "::1/128",
            "fe80::/10",
            "fd7a:115c:a1e0::/48",
            "fd01:db8:1111::/64"
        ];

        internal static string BuildBlockedRanges(IEnumerable<string> excludedCidrs)
        {
            List<(UInt128 Start, UInt128 End)> excluded = excludedCidrs
                .Select(ParseCidr)
                .OrderBy(r => r.Start)
                .ToList();

            var blocked = new List<(UInt128 Start, UInt128 End)>();
            UInt128 cursor = UInt128.Zero;
            bool exhausted = false;

            foreach ((UInt128 start, UInt128 end) in excluded)
            {
                if (exhausted)
                    break;
                if (start > cursor)
                    blocked.Add((cursor, start - 1));
                if (end == UInt128.MaxValue)
                {
                    exhausted = true;
                    break;
                }
                if (end + 1 > cursor)
                    cursor = end + 1;
            }

            if (!exhausted)
                blocked.Add((cursor, UInt128.MaxValue));

            return string.Join(',', blocked.Select(r => r.Start == r.End ? Format(r.Start) : $"{Format(r.Start)}-{Format(r.End)}"));
        }

        internal static (UInt128 Start, UInt128 End) ParseCidr(string cidr)
        {
            string[] parts = cidr.Split('/');
            if (parts.Length != 2
                || !IPAddress.TryParse(parts[0], out IPAddress? address)
                || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6
                || !int.TryParse(parts[1], out int length)
                || length is < 0 or > 128)
            {
                throw new FormatException($"Prefixo IPv6 inválido: '{cidr}'.");
            }

            UInt128 value = ToUInt128(address);
            UInt128 hostMask = length == 128 ? UInt128.Zero : UInt128.MaxValue >> length;
            UInt128 start = value & ~hostMask;
            return (start, start | hostMask);
        }

        private static UInt128 ToUInt128(IPAddress address)
        {
            UInt128 value = UInt128.Zero;
            foreach (byte b in address.GetAddressBytes())
                value = (value << 8) | b;
            return value;
        }

        private static string Format(UInt128 value)
        {
            var bytes = new byte[16];
            for (int i = 15; i >= 0; i--)
            {
                bytes[i] = (byte)(value & 0xFF);
                value >>= 8;
            }
            return new IPAddress(bytes).ToString();
        }
    }
}
