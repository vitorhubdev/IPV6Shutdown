namespace IPV6Shutdown.Tests
{
    using IPV6Shutdown;
    using Xunit;

    public class DisabledComponentsPolicyTests
    {
        [Fact]
        public void ApplyPreferIpv4_sets_bit_when_missing()
        {
            (int value, bool newlySet) = DisabledComponentsPolicy.ApplyPreferIpv4(0);
            Assert.Equal(0x20, value);
            Assert.True(newlySet);
        }

        [Fact]
        public void ApplyPreferIpv4_preserves_existing_bits()
        {
            (int value, bool newlySet) = DisabledComponentsPolicy.ApplyPreferIpv4(0x10);
            Assert.Equal(0x30, value);
            Assert.True(newlySet);
        }

        [Fact]
        public void ApplyPreferIpv4_skips_when_already_set()
        {
            (int value, bool newlySet) = DisabledComponentsPolicy.ApplyPreferIpv4(0x20);
            Assert.Equal(0x20, value);
            Assert.False(newlySet);
        }

        [Fact]
        public void RevertPreferIpv4_clears_bit_only()
        {
            (int? value, bool removeProperty, bool changed) = DisabledComponentsPolicy.RevertPreferIpv4(0x30);
            Assert.Equal(0x10, value);
            Assert.False(removeProperty);
            Assert.True(changed);
        }

        [Fact]
        public void RevertPreferIpv4_removes_property_when_zero()
        {
            (int? value, bool removeProperty, bool changed) = DisabledComponentsPolicy.RevertPreferIpv4(0x20);
            Assert.Null(value);
            Assert.True(removeProperty);
            Assert.True(changed);
        }

        [Fact]
        public void RevertPreferIpv4_removes_property_for_disable_all()
        {
            (int? value, bool removeProperty, bool changed) = DisabledComponentsPolicy.RevertPreferIpv4(0xFF);
            Assert.Null(value);
            Assert.True(removeProperty);
            Assert.True(changed);
        }

        [Fact]
        public void RevertPreferIpv4_noop_when_bit_absent()
        {
            (int? value, bool removeProperty, bool changed) = DisabledComponentsPolicy.RevertPreferIpv4(0x10);
            Assert.Equal(0x10, value);
            Assert.False(removeProperty);
            Assert.False(changed);
        }
    }
}
