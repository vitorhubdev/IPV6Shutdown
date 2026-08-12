using System.Xml;

namespace IPV6Shutdown
{
    /// <summary>Pure validation helpers for the scheduled watchdog task (unit-testable).</summary>
    internal static class WatchdogTaskValidation
    {
        private const double TwoMinutes = 2.0;
        private const double IntervalToleranceMinutes = 0.02;

        internal static bool IsWatchdogIntervalTwoMinutes(string? intervalRaw)
        {
            if (string.IsNullOrWhiteSpace(intervalRaw))
                return false;

            string interval = intervalRaw.Trim();

            if (interval.Equals("PT2M", StringComparison.OrdinalIgnoreCase))
                return true;

            if (TimeSpan.TryParse(interval, out TimeSpan parsed))
                return IsApproximatelyTwoMinutes(parsed.TotalMinutes);

            try
            {
                TimeSpan iso = XmlConvert.ToTimeSpan(interval);
                return IsApproximatelyTwoMinutes(iso.TotalMinutes);
            }
            catch (FormatException)
            {
            }
            catch (ArgumentException)
            {
            }

            return false;
        }

        internal static bool IsIllegalWatchdogDuration(string? durationRaw)
        {
            if (string.IsNullOrWhiteSpace(durationRaw))
                return false;

            return durationRaw.Contains("P99999999", StringComparison.OrdinalIgnoreCase)
                || durationRaw.Contains("99999999", StringComparison.OrdinalIgnoreCase);
        }

        internal static bool IsInvalidTaskDurationError(string text) =>
            text.Contains("P99999999", StringComparison.OrdinalIgnoreCase)
            || (text.Contains("Duration", StringComparison.OrdinalIgnoreCase)
                && (text.Contains("formatado incorretamente", StringComparison.OrdinalIgnoreCase)
                    || text.Contains("fora do intervalo", StringComparison.OrdinalIgnoreCase)
                    || text.Contains("incorrectly formatted", StringComparison.OrdinalIgnoreCase)
                    || text.Contains("out of range", StringComparison.OrdinalIgnoreCase)));

        private static bool IsApproximatelyTwoMinutes(double totalMinutes) =>
            Math.Abs(totalMinutes - TwoMinutes) <= IntervalToleranceMinutes;
    }
}
