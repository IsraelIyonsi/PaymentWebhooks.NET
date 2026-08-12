namespace PaymentWebhooks;

/// <summary>
/// The outcome of a webhook signature verification attempt.
/// </summary>
public sealed class WebhookVerificationResult
{
    private WebhookVerificationResult(bool isValid, WebhookVerificationFailureReason failureReason)
    {
        IsValid = isValid;
        FailureReason = failureReason;
    }

    /// <summary>
    /// Gets a value indicating whether the webhook signature is valid.
    /// </summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets the reason verification failed. Equal to <see cref="WebhookVerificationFailureReason.None"/>
    /// when <see cref="IsValid"/> is true.
    /// </summary>
    public WebhookVerificationFailureReason FailureReason { get; }

    /// <summary>
    /// Creates a result representing a successfully verified webhook.
    /// </summary>
    /// <returns>A successful <see cref="WebhookVerificationResult"/>.</returns>
    public static WebhookVerificationResult Success() => new(true, WebhookVerificationFailureReason.None);

    /// <summary>
    /// Creates a result representing a failed verification attempt.
    /// </summary>
    /// <param name="reason">The specific reason verification failed.</param>
    /// <returns>A failed <see cref="WebhookVerificationResult"/>.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="reason"/> is <see cref="WebhookVerificationFailureReason.None"/>.
    /// </exception>
    public static WebhookVerificationResult Failure(WebhookVerificationFailureReason reason)
    {
        if (reason == WebhookVerificationFailureReason.None)
        {
            throw new ArgumentException("A failure result requires a specific failure reason.", nameof(reason));
        }

        return new WebhookVerificationResult(false, reason);
    }
}
