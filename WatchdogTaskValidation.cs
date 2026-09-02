using System.IO;
using System.Xml;

namespace IPV6Shutdown
{
    internal enum WatchdogConfigurationState
    {
        Healthy,
        Missing,
        Disabled,
        Invalid
    }

    internal sealed record WatchdogTaskSnapshot(
        bool Exists,
        bool Enabled,
        bool HasStartupTrigger,
        string Interval,
        string Duration,
        bool StartWhenAvailable,
        string UserId,
        string RunLevel,
        string ActionExecute,
        string ActionArguments);

    internal sealed record WatchdogConfigurationResult(
        WatchdogConfigurationState State,
        string Reason);

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

        internal static WatchdogConfigurationResult EvaluateConfiguration(WatchdogTaskSnapshot snapshot)
        {
            if (!snapshot.Exists)
                return new(WatchdogConfigurationState.Missing, "tarefa não encontrada");

            if (!snapshot.Enabled)
                return new(WatchdogConfigurationState.Disabled, "tarefa desativada");

            if (!snapshot.HasStartupTrigger)
                return new(WatchdogConfigurationState.Invalid, "trigger de inicialização ausente");

            if (!IsWatchdogIntervalTwoMinutes(snapshot.Interval))
                return new(WatchdogConfigurationState.Invalid,
                    $"intervalo periódico inválido ('{snapshot.Interval}')");

            if (IsIllegalWatchdogDuration(snapshot.Duration))
                return new(WatchdogConfigurationState.Invalid,
                    $"duração periódica inválida ('{snapshot.Duration}')");

            if (!snapshot.StartWhenAvailable)
                return new(WatchdogConfigurationState.Invalid, "StartWhenAvailable desativado");

            if (!IsSystemPrincipal(snapshot.UserId))
                return new(WatchdogConfigurationState.Invalid,
                    $"principal inesperado ('{snapshot.UserId}')");

            if (!snapshot.RunLevel.Equals("Highest", StringComparison.OrdinalIgnoreCase))
                return new(WatchdogConfigurationState.Invalid,
                    $"RunLevel inesperado ('{snapshot.RunLevel}')");

            string executable = Path.GetFileName(snapshot.ActionExecute);
            if (!executable.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase))
                return new(WatchdogConfigurationState.Invalid,
                    $"ação inesperada ('{snapshot.ActionExecute}')");

            if (!snapshot.ActionArguments.Contains("-EncodedCommand", StringComparison.OrdinalIgnoreCase))
                return new(WatchdogConfigurationState.Invalid,
                    "ação não contém -EncodedCommand");

            return new(WatchdogConfigurationState.Healthy, "configuração válida");
        }

        private static bool IsSystemPrincipal(string userId)
        {
            string normalized = userId.Trim();
            return normalized.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase)
                || normalized.Equals("S-1-5-18", StringComparison.OrdinalIgnoreCase)
                || normalized.EndsWith("\\SYSTEM", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsApproximatelyTwoMinutes(double totalMinutes) =>
            Math.Abs(totalMinutes - TwoMinutes) <= IntervalToleranceMinutes;
    }
}
