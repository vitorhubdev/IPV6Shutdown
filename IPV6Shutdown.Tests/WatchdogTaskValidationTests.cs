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
    }
}
