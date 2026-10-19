namespace IPV6Shutdown.Tests
{
    using IPV6Shutdown;
    using Xunit;

    public class OriginalStateTests
    {
        [Fact]
        public void Json_round_trip_preserves_all_fields()
        {
            var state = new OriginalState
            {
                Mode = "full",
                DisabledBindings = ["Ethernet", "Wi-Fi 'casa'"],
                IpHelperStartType = "Automatic",
                IpHelperWasRunning = true,
                DisabledComponentsPresent = true,
                DisabledComponentsValue = 0x20,
                CustomProtect = ["meuvpn"],
                RegistryWrittenUtc = new DateTime(2026, 10, 19, 12, 0, 0, DateTimeKind.Utc)
            };
            state.Tunnels["Teredo"] = "Default";

            OriginalState? loaded = OriginalState.FromJson(state.ToJson());

            Assert.NotNull(loaded);
            Assert.Equal("full", loaded.Mode);
            Assert.Equal(state.DisabledBindings, loaded.DisabledBindings);
            Assert.Equal("Automatic", loaded.IpHelperStartType);
            Assert.True(loaded.IpHelperWasRunning);
            Assert.True(loaded.DisabledComponentsPresent);
            Assert.Equal(0x20, loaded.DisabledComponentsValue);
            Assert.Equal("Default", loaded.Tunnels["teredo"]);
            Assert.Equal(["meuvpn"], loaded.CustomProtect);
            Assert.Equal(state.RegistryWrittenUtc, loaded.RegistryWrittenUtc);
        }

        [Theory]
        [InlineData("")]
        [InlineData("not json")]
        [InlineData("[1,2]")]
        public void Corrupt_state_returns_null(string json)
        {
            Assert.Null(OriginalState.FromJson(json));
        }

        [Fact]
        public void Save_load_delete_round_trip_on_disk()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ipv6shutdown-test-" + Guid.NewGuid().ToString("N"));
            string path = Path.Combine(dir, "state.json");
            try
            {
                new OriginalState { DisabledBindings = ["Ethernet"] }.Save(path);
                Assert.Equal(["Ethernet"], OriginalState.Load(path)!.DisabledBindings);

                OriginalState.Delete(path);
                Assert.Null(OriginalState.Load(path));
                Assert.False(Directory.Exists(dir));
            }
            finally
            {
                if (Directory.Exists(dir))
                    Directory.Delete(dir, recursive: true);
            }
        }
    }
}
