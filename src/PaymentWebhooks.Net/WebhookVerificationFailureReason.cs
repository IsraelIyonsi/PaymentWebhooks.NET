namespace PaymentWebhooks;

/// <summary>
/// Enumerates the reasons a webhook signature verification attempt can fail.
/// </summary>
public enum WebhookVerificationFailureReason
{
    /// <summary>
    /// Verification succeeded; no failure occurred.
    /// </summary>
    None = 0,

    /// <summary>
    /// A required signature or timestamp header was not present in the request.
    /// </summary>
    MissingHeader,

    /// <summary>
    /// A required header was present but did not match the format the scheme expects.
    /// </summary>
    MalformedSignatureHeader,

    /// <summary>
    /// None of the signatures supplied by the sender used a signature version this verifier supports.
    /// </summary>
    UnsupportedSignatureVersion,

    /// <summary>
    /// The timestamp carried by the request fell outside the configured tolerance window.
    /// </summary>
    TimestampOutOfTolerance,

    /// <summary>
    /// The computed signature did not match any signature supplied by the sender.
    /// </summary>
    SignatureMismatch,
}
