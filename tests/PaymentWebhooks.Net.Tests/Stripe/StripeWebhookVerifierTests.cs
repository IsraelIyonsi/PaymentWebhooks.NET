using System.Text;
using PaymentWebhooks.Tests.Support;

namespace PaymentWebhooks.Tests.Stripe;

public class StripeWebhookVerifierTests
{
    private static readonly StripeFixture Fixture = FixtureLoader.Load<StripeFixture>("stripe-known-answer.json");

    // The known-answer fixture carries a fixed historical timestamp so it reproduces the
    // vendor signing-string exactly. These cases isolate signature-construction correctness
    // from timestamp-tolerance behavior, which has its own dedicated tests below, so they run
    // against a tolerance wide enough that the fixture's age is never the deciding factor.
    private static readonly TimeSpan FixtureAgnosticTolerance = TimeSpan.FromDays(36_500);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Constructor_RejectsNullOrEmptySecret(string? secret)
    {
        Assert.ThrowsAny<ArgumentException>(() => new StripeWebhookVerifier(secret!));
    }

    [Fact]
    public void Verify_NullHeaders_ThrowsArgumentNullException()
    {
        var verifier = new StripeWebhookVerifier(Fixture.Secret);

        Assert.Throws<ArgumentNullException>(
            () => verifier.Verify(Encoding.UTF8.GetBytes(Fixture.Payload), null!));
    }

    public static IEnumerable<object[]> KnownAnswerCases()
    {
        var validHeader = $"t={Fixture.Timestamp},v1={Fixture.Signature}";

        yield return new object[]
        {
            Fixture.Payload,
            new Dictionary<string, string> { [StripeWebhookVerifier.SignatureHeaderName] = validHeader },
            true,
            WebhookVerificationFailureReason.None,
        };

        yield return new object[]
        {
            Fixture.Payload + "-tampered",
            new Dictionary<string, string> { [StripeWebhookVerifier.SignatureHeaderName] = validHeader },
            false,
            WebhookVerificationFailureReason.SignatureMismatch,
        };

        yield return new object[]
        {
            Fixture.Payload,
            new Dictionary<string, string>
            {
                ["stripe-signature"] = validHeader,
            },
            true,
            WebhookVerificationFailureReason.None,
        };

        yield return new object[]
        {
            Fixture.Payload,
            new Dictionary<string, string>(),
            false,
            WebhookVerificationFailureReason.MissingHeader,
        };

        yield return new object[]
        {
            Fixture.Payload,
            new Dictionary<string, string> { [StripeWebhookVerifier.SignatureHeaderName] = "not-a-valid-header" },
            false,
            WebhookVerificationFailureReason.MalformedSignatureHeader,
        };

        yield return new object[]
        {
            Fixture.Payload,
            new Dictionary<string, string>
            {
                [StripeWebhookVerifier.SignatureHeaderName] = $"t=not-a-number,v1={Fixture.Signature}",
            },
            false,
            WebhookVerificationFailureReason.MalformedSignatureHeader,
        };

        yield return new object[]
        {
            Fixture.Payload,
            new Dictionary<string, string>
            {
                [StripeWebhookVerifier.SignatureHeaderName] = $"t={Fixture.Timestamp}",
            },
            false,
            WebhookVerificationFailureReason.UnsupportedSignatureVersion,
        };

        yield return new object[]
        {
            Fixture.Payload,
            new Dictionary<string, string>
            {
                [StripeWebhookVerifier.SignatureHeaderName] =
                    $"t={Fixture.Timestamp},v0=irrelevant_old_scheme_signature,v1={Fixture.Signature}",
            },
            true,
            WebhookVerificationFailureReason.None,
        };

        yield return new object[]
        {
            Fixture.Payload,
            new Dictionary<string, string>
            {
                [StripeWebhookVerifier.SignatureHeaderName] =
                    $"t={Fixture.Timestamp},v1=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef,v1={Fixture.Signature}",
            },
            true,
            WebhookVerificationFailureReason.None,
        };
    }

    [Theory]
    [MemberData(nameof(KnownAnswerCases))]
    public void Verify_KnownAnswerAndEdgeCases_ReturnsExpectedResult(
        string payload,
        Dictionary<string, string> headers,
        bool expectedValid,
        WebhookVerificationFailureReason expectedReason)
    {
        var verifier = new StripeWebhookVerifier(Fixture.Secret, FixtureAgnosticTolerance);

        var result = verifier.Verify(Encoding.UTF8.GetBytes(payload), headers);

        Assert.Equal(expectedValid, result.IsValid);
        Assert.Equal(expectedReason, result.FailureReason);
    }

    [Fact]
    public void Verify_TimestampWithinCustomTolerance_Succeeds()
    {
        const string secret = "whsec_custom_tolerance_secret";
        const string payload = "{\"id\":\"evt_custom\"}";
        var timestamp = DateTimeOffset.UtcNow.AddMinutes(-8).ToUnixTimeSeconds();
        var signature = IndependentHmacOracle.StripeSignature(secret, timestamp, payload);
        var headers = new Dictionary<string, string>
        {
            [StripeWebhookVerifier.SignatureHeaderName] = $"t={timestamp},v1={signature}",
        };
        var verifier = new StripeWebhookVerifier(secret, TimeSpan.FromMinutes(10));

        var result = verifier.Verify(Encoding.UTF8.GetBytes(payload), headers);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Verify_StaleTimestampBeyondTolerance_FailsEvenWithValidSignature()
    {
        const string secret = "whsec_replay_protection_secret";
        const string payload = "{\"id\":\"evt_stale\"}";
        var staleTimestamp = DateTimeOffset.UtcNow.AddSeconds(-600).ToUnixTimeSeconds();
        var signature = IndependentHmacOracle.StripeSignature(secret, staleTimestamp, payload);
        var headers = new Dictionary<string, string>
        {
            [StripeWebhookVerifier.SignatureHeaderName] = $"t={staleTimestamp},v1={signature}",
        };
        var verifier = new StripeWebhookVerifier(secret);

        var result = verifier.Verify(Encoding.UTF8.GetBytes(payload), headers);

        Assert.False(result.IsValid);
        Assert.Equal(WebhookVerificationFailureReason.TimestampOutOfTolerance, result.FailureReason);
    }

    [Fact]
    public void Verify_FutureTimestampBeyondTolerance_Fails()
    {
        const string secret = "whsec_future_clock_skew_secret";
        const string payload = "{\"id\":\"evt_future\"}";
        var futureTimestamp = DateTimeOffset.UtcNow.AddSeconds(600).ToUnixTimeSeconds();
        var signature = IndependentHmacOracle.StripeSignature(secret, futureTimestamp, payload);
        var headers = new Dictionary<string, string>
        {
            [StripeWebhookVerifier.SignatureHeaderName] = $"t={futureTimestamp},v1={signature}",
        };
        var verifier = new StripeWebhookVerifier(secret);

        var result = verifier.Verify(Encoding.UTF8.GetBytes(payload), headers);

        Assert.False(result.IsValid);
        Assert.Equal(WebhookVerificationFailureReason.TimestampOutOfTolerance, result.FailureReason);
    }

    [Fact]
    public void Verify_WrongSecret_FailsWithSignatureMismatch()
    {
        var verifier = new StripeWebhookVerifier(
            "whsec_a_completely_different_secret", FixtureAgnosticTolerance);
        var headers = new Dictionary<string, string>
        {
            [StripeWebhookVerifier.SignatureHeaderName] = $"t={Fixture.Timestamp},v1={Fixture.Signature}",
        };

        var result = verifier.Verify(Encoding.UTF8.GetBytes(Fixture.Payload), headers);

        Assert.False(result.IsValid);
        Assert.Equal(WebhookVerificationFailureReason.SignatureMismatch, result.FailureReason);
    }

    [Fact]
    public void Verify_UppercaseHexSignature_Succeeds()
    {
        var validHeader = $"t={Fixture.Timestamp},v1={Fixture.Signature.ToUpperInvariant()}";
        var verifier = new StripeWebhookVerifier(Fixture.Secret, FixtureAgnosticTolerance);
        var headers = new Dictionary<string, string>
        {
            [StripeWebhookVerifier.SignatureHeaderName] = validHeader,
        };

        var result = verifier.Verify(Encoding.UTF8.GetBytes(Fixture.Payload), headers);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Verify_TimestampWithLeadingZero_UsesRawSubstringInSignedString()
    {
        const string secret = "whsec_leading_zero_secret";
        const string payload = "{\"id\":\"evt_leading_zero\"}";
        const string rawTimestamp = "0099999999";
        var signature = IndependentHmacOracle.StripeSignature(secret, rawTimestamp, payload);
        var headers = new Dictionary<string, string>
        {
            [StripeWebhookVerifier.SignatureHeaderName] = $"t={rawTimestamp},v1={signature}",
        };
        var verifier = new StripeWebhookVerifier(secret, FixtureAgnosticTolerance);

        var result = verifier.Verify(Encoding.UTF8.GetBytes(payload), headers);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Verify_DuplicateTimestampComponent_FailsAsMalformed()
    {
        var headers = new Dictionary<string, string>
        {
            [StripeWebhookVerifier.SignatureHeaderName] =
                $"t={Fixture.Timestamp},t={Fixture.Timestamp},v1={Fixture.Signature}",
        };
        var verifier = new StripeWebhookVerifier(Fixture.Secret, FixtureAgnosticTolerance);

        var result = verifier.Verify(Encoding.UTF8.GetBytes(Fixture.Payload), headers);

        Assert.False(result.IsValid);
        Assert.Equal(WebhookVerificationFailureReason.MalformedSignatureHeader, result.FailureReason);
    }

    [Fact]
    public void Verify_WrongSignatureAndStaleTimestamp_ReportsSignatureMismatchNotTimestamp()
    {
        const string secret = "whsec_ordering_secret";
        const string payload = "{\"id\":\"evt_ordering\"}";
        var staleTimestamp = DateTimeOffset.UtcNow.AddSeconds(-600).ToUnixTimeSeconds();
        var headers = new Dictionary<string, string>
        {
            [StripeWebhookVerifier.SignatureHeaderName] =
                $"t={staleTimestamp},v1=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        };
        var verifier = new StripeWebhookVerifier(secret);

        var result = verifier.Verify(Encoding.UTF8.GetBytes(payload), headers);

        Assert.False(result.IsValid);
        Assert.Equal(WebhookVerificationFailureReason.SignatureMismatch, result.FailureReason);
    }

    [Fact]
    public void Verify_ImplementsIWebhookVerifier()
    {
        IWebhookVerifier verifier = new StripeWebhookVerifier(Fixture.Secret, FixtureAgnosticTolerance);
        var headers = new Dictionary<string, string>
        {
            [StripeWebhookVerifier.SignatureHeaderName] = $"t={Fixture.Timestamp},v1={Fixture.Signature}",
        };

        var result = verifier.Verify(Encoding.UTF8.GetBytes(Fixture.Payload), headers);

        Assert.True(result.IsValid);
    }
}
