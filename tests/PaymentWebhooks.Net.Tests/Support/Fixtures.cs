namespace PaymentWebhooks.Tests.Support;

internal sealed class StripeFixture
{
    public string Description { get; set; } = string.Empty;

    public string Secret { get; set; } = string.Empty;

    public string Payload { get; set; } = string.Empty;

    public long Timestamp { get; set; }

    public string Signature { get; set; } = string.Empty;
}

internal sealed class GitHubFixture
{
    public string Description { get; set; } = string.Empty;

    public string Secret { get; set; } = string.Empty;

    public string Payload { get; set; } = string.Empty;

    public string Signature { get; set; } = string.Empty;
}

internal sealed class PaystackFixture
{
    public string Description { get; set; } = string.Empty;

    public string SecretKey { get; set; } = string.Empty;

    public string Payload { get; set; } = string.Empty;

    public string Signature { get; set; } = string.Empty;
}

internal sealed class StandardWebhooksFixture
{
    public string Description { get; set; } = string.Empty;

    public string MessageId { get; set; } = string.Empty;

    public long Timestamp { get; set; }

    public string Payload { get; set; } = string.Empty;

    public string Secret { get; set; } = string.Empty;

    public string Signature { get; set; } = string.Empty;
}

internal sealed class FlutterwaveFixture
{
    public string Description { get; set; } = string.Empty;

    public string SecretHash { get; set; } = string.Empty;
}

internal sealed class ShopifyFixture
{
    public string Description { get; set; } = string.Empty;

    public string Secret { get; set; } = string.Empty;

    public string Payload { get; set; } = string.Empty;

    public string Signature { get; set; } = string.Empty;
}
