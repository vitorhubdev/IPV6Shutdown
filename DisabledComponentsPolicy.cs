namespace IPV6Shutdown
{
    /// <summary>Pure helpers for DisabledComponents registry DWORD (unit-testable).</summary>
    internal static class DisabledComponentsPolicy
    {
        internal const int PreferIpv4 = 0x20;
        internal const int DisableAll = 0xFF;

        internal static (int value, bool newlySet) ApplyPreferIpv4(int current)
        {
            if ((current & PreferIpv4) != 0)
                return (current, false);
            return (current | PreferIpv4, true);
        }

        internal static (int? value, bool removeProperty, bool changed) RevertPreferIpv4(int current)
        {
            if (current == DisableAll)
                return (null, true, true);

            if ((current & PreferIpv4) == 0)
                return (current, false, false);

            int newValue = current & ~PreferIpv4;
            if (newValue == 0)
                return (null, true, true);
            return (newValue, false, true);
        }

        internal static bool HasPreferIpv4(int value) => (value & PreferIpv4) != 0;

        internal static bool IsDisableAll(int value) => value == DisableAll;

        internal static string FormatStatusMarkup(int value)
        {
            if (IsDisableAll(value))
                return "[green]0xFF — IPv6 desativado na pilha[/]";
            if (value == 0)
                return "[red]não definido — IPv6 habilitado na pilha[/]";
            if (HasPreferIpv4(value))
                return $"[green]0x{value:X2} — Prefer IPv4 (0x20)[/]";
            return $"[yellow]0x{value:X2} — parcial[/]";
        }
    }
}
