namespace PaymentWebhooks.Tests.Core;

public class WebhookVerificationResultTests
{
    [Fact]
    public void Success_ReturnsValidResultWithNoFailureReason()
    {
        var result = WebhookVerificationResult.Success();

        Assert.True(result.IsValid);
        Assert.Equal(WebhookVerificationFailureReason.None, result.FailureReason);
    }

    public static IEnumerable<object[]> NonNoneFailureReasons()
    {
        foreach (WebhookVerificationFailureReason reason in Enum.GetValues<WebhookVerificationFailureReason>())
        {
            if (reason != WebhookVerificationFailureReason.None)
            {
                yield return new object[] { reason };
            }
        }
    }

    [Theory]
    [MemberData(nameof(NonNoneFailureReasons))]
    public void Failure_ReturnsInvalidResultCarryingTheReason(WebhookVerificationFailureReason reason)
    {
        var result = WebhookVerificationResult.Failure(reason);

        Assert.False(result.IsValid);
        Assert.Equal(reason, result.FailureReason);
    }

    [Fact]
    public void Failure_WithNoneReason_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => WebhookVerificationResult.Failure(WebhookVerificationFailureReason.None));
    }
}
