namespace PaymentWebhooks.Tests.Core;

public class WebhookVerificationDefaultsTests
{
    [Fact]
    public void DefaultTimestampToleranceSeconds_IsThreeHundred()
    {
        Assert.Equal(300, WebhookVerificationDefaults.DefaultTimestampToleranceSeconds);
    }

    [Fact]
    public void DefaultTimestampTolerance_MatchesSecondsConstant()
    {
        Assert.Equal(
            TimeSpan.FromSeconds(WebhookVerificationDefaults.DefaultTimestampToleranceSeconds),
            WebhookVerificationDefaults.DefaultTimestampTolerance);
    }
}
