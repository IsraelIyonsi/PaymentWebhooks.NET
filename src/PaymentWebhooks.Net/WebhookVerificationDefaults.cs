namespace PaymentWebhooks;

/// <summary>
/// Default configuration values shared across webhook verifiers.
/// </summary>
public static class WebhookVerificationDefaults
{
    /// <summary>
    /// The default timestamp tolerance, in seconds, that timestamped webhook schemes use
    /// to reject stale or replayed requests.
    /// </summary>
    public const int DefaultTimestampToleranceSeconds = 300;

    /// <summary>
    /// The default timestamp tolerance that timestamped webhook schemes use to reject
    /// stale or replayed requests.
    /// </summary>
    public static readonly TimeSpan DefaultTimestampTolerance =
        TimeSpan.FromSeconds(DefaultTimestampToleranceSeconds);
}
