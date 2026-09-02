namespace IPV6Shutdown.Tests
{
    using IPV6Shutdown;
    using Xunit;

    public class WatchdogTaskValidationTests
    {
        [Theory]
        [InlineData("PT2M")]
        [InlineData("00:02:00")]
        [InlineData("0:02:00")]
        public void IsWatchdogIntervalTwoMinutes_accepts_two_minute_representations(string interval)
        {
            Assert.True(WatchdogTaskValidation.IsWatchdogIntervalTwoMinutes(interval));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("PT1M")]
        [InlineData("00:05:00")]
        [InlineData("garbage")]
        public void IsWatchdogIntervalTwoMinutes_rejects_non_two_minute(string? interval)
        {
            Assert.False(WatchdogTaskValidation.IsWatchdogIntervalTwoMinutes(interval));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void IsIllegalWatchdogDuration_treats_blank_as_indefinite(string? duration)
        {
            Assert.False(WatchdogTaskValidation.IsIllegalWatchdogDuration(duration));
        }

        [Theory]
        [InlineData("P99999999DT23H59M59S")]
        [InlineData("contains-99999999-here")]
        public void IsIllegalWatchdogDuration_rejects_max_value_forms(string duration)
        {
            Assert.True(WatchdogTaskValidation.IsIllegalWatchdogDuration(duration));
        }

        [Fact]
        public void IsInvalidTaskDurationError_detects_scheduler_xml_errors()
        {
            Assert.True(WatchdogTaskValidation.IsInvalidTaskDurationError(
                "Duration:P99999999DT23H59M59S formatado incorretamente"));
            Assert.False(WatchdogTaskValidation.IsInvalidTaskDurationError("comando genérico falhou"));
        }

        [Fact]
        public void EvaluateConfiguration_accepts_boot_periodic_system_task()
        {
            WatchdogConfigurationResult result =
                WatchdogTaskValidation.EvaluateConfiguration(HealthySnapshot());

            Assert.Equal(WatchdogConfigurationState.Healthy, result.State);
        }

        [Fact]
        public void EvaluateConfiguration_rejects_missing_task()
        {
            WatchdogTaskSnapshot snapshot = HealthySnapshot() with { Exists = false };
            Assert.Equal(WatchdogConfigurationState.Missing,
                WatchdogTaskValidation.EvaluateConfiguration(snapshot).State);
        }

        [Fact]
        public void EvaluateConfiguration_rejects_disabled_task()
        {
            WatchdogTaskSnapshot snapshot = HealthySnapshot() with { Enabled = false };
            Assert.Equal(WatchdogConfigurationState.Disabled,
                WatchdogTaskValidation.EvaluateConfiguration(snapshot).State);
        }

        [Fact]
        public void EvaluateConfiguration_requires_startup_trigger()
        {
            WatchdogConfigurationResult result = WatchdogTaskValidation.EvaluateConfiguration(
                HealthySnapshot() with { HasStartupTrigger = false });

            Assert.Equal(WatchdogConfigurationState.Invalid, result.State);
            Assert.Contains("inicialização", result.Reason);
        }

        [Fact]
        public void EvaluateConfiguration_requires_start_when_available()
        {
            WatchdogConfigurationResult result = WatchdogTaskValidation.EvaluateConfiguration(
                HealthySnapshot() with { StartWhenAvailable = false });

            Assert.Equal(WatchdogConfigurationState.Invalid, result.State);
            Assert.Contains("StartWhenAvailable", result.Reason);
        }

        [Fact]
        public void EvaluateConfiguration_requires_system_highest_powershell()
        {
            Assert.Equal(WatchdogConfigurationState.Invalid,
                WatchdogTaskValidation.EvaluateConfiguration(
                    HealthySnapshot() with { UserId = "usuario" }).State);
            Assert.Equal(WatchdogConfigurationState.Invalid,
                WatchdogTaskValidation.EvaluateConfiguration(
                    HealthySnapshot() with { RunLevel = "Limited" }).State);
            Assert.Equal(WatchdogConfigurationState.Invalid,
                WatchdogTaskValidation.EvaluateConfiguration(
                    HealthySnapshot() with { ActionExecute = "cmd.exe" }).State);
        }

        private static WatchdogTaskSnapshot HealthySnapshot() => new(
            Exists: true,
            Enabled: true,
            HasStartupTrigger: true,
            Interval: "PT2M",
            Duration: "",
            StartWhenAvailable: true,
            UserId: "SYSTEM",
            RunLevel: "Highest",
            ActionExecute: "powershell.exe",
            ActionArguments: "-NoProfile -EncodedCommand AAAA");
    }
}
