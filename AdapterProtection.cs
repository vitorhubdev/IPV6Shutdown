namespace IPV6Shutdown
{
    /// <summary>
    /// Decide quais adaptadores nunca devem ter o IPv6 desligado (VPNs/overlays que dependem dele).
    /// Pure helpers (unit-testable); o watchdog usa a mesma lista.
    /// </summary>
    internal static class AdapterProtection
    {
        /// <summary>Trechos (minúsculos) do nome/descrição de adaptadores de VPN conhecidos.</summary>
        internal static readonly string[] KnownPatterns =
        [
            "tailscale",
            "cloudflare warp",
            "cloudflarewarp",
            "wireguard",
            "wintun",
            "nordlynx",
            "protonvpn",
            "proton vpn",
            "mullvad",
            "windscribe",
            "expressvpn",
            "zerotier",
            "hamachi",
            "openvpn",
            "tap-windows",
            "anyconnect",
            "globalprotect",
            "pangp virtual",
            "forticlient",
            "fortinet"
        ];

        internal static IReadOnlyList<string> Normalize(IEnumerable<string>? custom) =>
            KnownPatterns
                .Concat((custom ?? []).Select(p => p.Trim().ToLowerInvariant()).Where(p => p.Length > 0))
                .Distinct(StringComparer.Ordinal)
                .ToList();

        /// <summary>Retorna o padrão que protege o adaptador, ou null se ele pode ser bloqueado.</summary>
        internal static string? FindMatch(string name, string description, IEnumerable<string>? custom = null)
        {
            string text = $"{name} {description}".ToLowerInvariant();
            foreach (string pattern in Normalize(custom))
            {
                if (text.Contains(pattern, StringComparison.Ordinal))
                    return pattern;
            }
            return null;
        }

        internal static bool IsValidCustomPattern(string? pattern) =>
            !string.IsNullOrWhiteSpace(pattern)
            && pattern.Length <= 64
            && pattern.All(c => !char.IsControl(c) && c is not ('\'' or '"' or '`' or '$'));
    }
}
