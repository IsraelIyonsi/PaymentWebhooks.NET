using System.Text;
using PaymentWebhooks.Tests.Support;

namespace PaymentWebhooks.Tests.StandardWebhooks;

public class StandardWebhooksVerifierTests
{
    private static readonly StandardWebhooksFixture Fixture =
        FixtureLoader.Load<StandardWebhooksFixture>("standard-webhooks-known-answer.json");

    // The official Svix/Standard Webhooks worked example carries a fixed historical timestamp
    // so it reproduces the vendor signing-string exactly. These cases isolate signature
    // construction correctness from timestamp-tolerance behavior, which has its own dedicated
    // tests below, so they run against a tolerance wide enough that the fixture's age is never
    // the deciding factor.
    private static readonly TimeSpan FixtureAgnosticTolerance = TimeSpan.FromDays(36_500);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Constructor_RejectsNullOrEmptySecret(string? secret)
    {
        Assert.ThrowsAny<ArgumentException>(() => new PaymentWebhooks.StandardWebhooksVerifier(secret!));
    }

    [Theory]
    [InlineData("whsec_not-valid-base64!!!")]
    [InlineData("not-valid-base64!!!")]
    public void Constructor_RejectsSecretThatIsNotValidBase64(string secret)
    {
        Assert.ThrowsAny<ArgumentException>(() => new PaymentWebhooks.StandardWebhooksVerifier(secret));
    }

    [Fact]
    public void Constructor_AcceptsSecretWithoutWhsecPrefix()
    {
        var rawBase64 = Fixture.Secret["whsec_".Length..];

        var exception = Record.Exception(() => new PaymentWebhooks.StandardWebhooksVerifier(rawBase64));

        Assert.Null(exception);
    }

    [Fact]
    public void Verify_NullHeaders_ThrowsArgumentNullException()
    {
        var verifier = new PaymentWebhooks.StandardWebhooksVerifier(Fixture.Secret);

        Assert.Throws<ArgumentNullException>(
            () => verifier.Verify(Encoding.UTF8.GetBytes(Fixture.Payload), null!));
    }

    private static Dictionary<string, string> ValidHeaders() => new()
    {
        [PaymentWebhooks.StandardWebhooksVerifier.MessageIdHeaderName] = Fixture.MessageId,
        [PaymentWebhooks.StandardWebhooksVerifier.TimestampHeaderName] =
            Fixture.Timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture),
        [PaymentWebhooks.StandardWebhooksVerifier.SignatureHeaderName] = Fixture.Signature,
    };

    public static IEnumerable<object[]> KnownAnswerCases()
    {
        yield return new object[]
        {
            Fixture.Payload,
            ValidHeaders(),
            true,
            WebhookVerificationFailureReason.None,
        };

        yield return new object[]
        {
            Fixture.Payload + "-tampered",
            ValidHeaders(),
            false,
            WebhookVerificationFailureReason.SignatureMismatch,
        };

        var missingId = ValidHeaders();
        missingId.Remove(PaymentWebhooks.StandardWebhooksVerifier.MessageIdHeaderName);
        yield return new object[]
        {
            Fixture.Payload,
            missingId,
            false,
            WebhookVerificationFailureReason.MissingHeader,
        };

        var missingTimestamp = ValidHeaders();
        missingTimestamp.Remove(PaymentWebhooks.StandardWebhooksVerifier.TimestampHeaderName);
        yield return new object[]
        {
            Fixture.Payload,
            missingTimestamp,
            false,
            WebhookVerificationFailureReason.MissingHeader,
        };

        var missingSignature = ValidHeaders();
        missingSignature.Remove(PaymentWebhooks.StandardWebhooksVerifier.SignatureHeaderName);
        yield return new object[]
        {
            Fixture.Payload,
            missingSignature,
            false,
            WebhookVerificationFailureReason.MissingHeader,
        };

        var nonNumericTimestamp = ValidHeaders();
        nonNumericTimestamp[PaymentWebhooks.StandardWebhooksVerifier.TimestampHeaderName] = "not-a-number";
        yield return new object[]
        {
            Fixture.Payload,
            nonNumericTimestamp,
            false,
            WebhookVerificationFailureReason.MalformedSignatureHeader,
        };

        var malformedSignatureList = ValidHeaders();
        malformedSignatureList[PaymentWebhooks.StandardWebhooksVerifier.SignatureHeaderName] = "no-comma-here";
        yield return new object[]
        {
            Fixture.Payload,
            malformedSignatureList,
            false,
            WebhookVerificationFailureReason.MalformedSignatureHeader,
        };

        var unsupportedVersion = ValidHeaders();
        unsupportedVersion[PaymentWebhooks.StandardWebhooksVerifier.SignatureHeaderName] = "v2,someFutureSignature==";
        yield return new object[]
        {
            Fixture.Payload,
            unsupportedVersion,
            false,
            WebhookVerificationFailureReason.UnsupportedSignatureVersion,
        };

        var multipleSignaturesOneValid = ValidHeaders();
        multipleSignaturesOneValid[PaymentWebhooks.StandardWebhooksVerifier.SignatureHeaderName] =
            $"v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= {Fixture.Signature}";
        yield return new object[]
        {
            Fixture.Payload,
            multipleSignaturesOneValid,
            true,
            WebhookVerificationFailureReason.None,
        };

        var oneInvalidBase64AmongMultiple = ValidHeaders();
        oneInvalidBase64AmongMultiple[PaymentWebhooks.StandardWebhooksVerifier.SignatureHeaderName] =
            $"v1,not-valid-base64!! {Fixture.Signature}";
        yield return new object[]
        {
            Fixture.Payload,
            oneInvalidBase64AmongMultiple,
            true,
            WebhookVerificationFailureReason.None,
        };

        var caseInsensitiveHeaders = new Dictionary<string, string>
        {
            ["webhook-id"] = Fixture.MessageId,
            ["Webhook-Timestamp"] = Fixture.Timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["WEBHOOK-SIGNATURE"] = Fixture.Signature,
        };
        yield return new object[]
        {
            Fixture.Payload,
            caseInsensitiveHeaders,
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
        var verifier = new PaymentWebhooks.StandardWebhooksVerifier(Fixture.Secret, FixtureAgnosticTolerance);

        var result = verifier.Verify(Encoding.UTF8.GetBytes(payload), headers);

        Assert.Equal(expectedValid, result.IsValid);
        Assert.Equal(expectedReason, result.FailureReason);
    }

    [Fact]
    public void Verify_WrongSecret_FailsWithSignatureMismatch()
    {
        var verifier = new PaymentWebhooks.StandardWebhooksVerifier(
            "d2hzZWNfYSBkaWZmZXJlbnQgc2VjcmV0", FixtureAgnosticTolerance);

        var result = verifier.Verify(Encoding.UTF8.GetBytes(Fixture.Payload), ValidHeaders());

        Assert.False(result.IsValid);
        Assert.Equal(WebhookVerificationFailureReason.SignatureMismatch, result.FailureReason);
    }

    [Fact]
    public void Verify_StaleTimestampBeyondTolerance_FailsEvenWithValidSignature()
    {
        const string secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
        const string messageId = "msg_replay_protection_test";
        const string payload = "{\"test\":\"stale\"}";
        var staleTimestamp = DateTimeOffset.UtcNow.AddSeconds(-600).ToUnixTimeSeconds();
        var signature = IndependentHmacOracle.StandardWebhooksSignature(secret, messageId, staleTimestamp, payload);
        var headers = new Dictionary<string, string>
        {
            [PaymentWebhooks.StandardWebhooksVerifier.MessageIdHeaderName] = messageId,
            [PaymentWebhooks.StandardWebhooksVerifier.TimestampHeaderName] =
                staleTimestamp.ToString(System.Globalization.CultureInfo.InvariantCulture),
            [PaymentWebhooks.StandardWebhooksVerifier.SignatureHeaderName] = signature,
        };
        var verifier = new PaymentWebhooks.StandardWebhooksVerifier(secret);

        var result = verifier.Verify(Encoding.UTF8.GetBytes(payload), headers);

        Assert.False(result.IsValid);
        Assert.Equal(WebhookVerificationFailureReason.TimestampOutOfTolerance, result.FailureReason);
    }

    [Fact]
    public void Verify_FutureTimestampBeyondTolerance_Fails()
    {
        const string secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
        const string messageId = "msg_future_clock_skew_test";
        const string payload = "{\"test\":\"future\"}";
        var futureTimestamp = DateTimeOffset.UtcNow.AddSeconds(600).ToUnixTimeSeconds();
        var signature = IndependentHmacOracle.StandardWebhooksSignature(secret, messageId, futureTimestamp, payload);
        var headers = new Dictionary<string, string>
        {
            [PaymentWebhooks.StandardWebhooksVerifier.MessageIdHeaderName] = messageId,
            [PaymentWebhooks.StandardWebhooksVerifier.TimestampHeaderName] =
                futureTimestamp.ToString(System.Globalization.CultureInfo.InvariantCulture),
            [PaymentWebhooks.StandardWebhooksVerifier.SignatureHeaderName] = signature,
        };
        var verifier = new PaymentWebhooks.StandardWebhooksVerifier(secret);

        var result = verifier.Verify(Encoding.UTF8.GetBytes(payload), headers);

        Assert.False(result.IsValid);
        Assert.Equal(WebhookVerificationFailureReason.TimestampOutOfTolerance, result.FailureReason);
    }

    [Fact]
    public void Verify_TimestampWithinCustomTolerance_Succeeds()
    {
        const string secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
        const string messageId = "msg_custom_tolerance_test";
        const string payload = "{\"test\":\"custom\"}";
        var timestamp = DateTimeOffset.UtcNow.AddMinutes(-8).ToUnixTimeSeconds();
        var signature = IndependentHmacOracle.StandardWebhooksSignature(secret, messageId, timestamp, payload);
        var headers = new Dictionary<string, string>
        {
            [PaymentWebhooks.StandardWebhooksVerifier.MessageIdHeaderName] = messageId,
            [PaymentWebhooks.StandardWebhooksVerifier.TimestampHeaderName] =
                timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture),
            [PaymentWebhooks.StandardWebhooksVerifier.SignatureHeaderName] = signature,
        };
        var verifier = new PaymentWebhooks.StandardWebhooksVerifier(secret, TimeSpan.FromMinutes(10));

        var result = verifier.Verify(Encoding.UTF8.GetBytes(payload), headers);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Verify_ImplementsIWebhookVerifier()
    {
        IWebhookVerifier verifier =
            new PaymentWebhooks.StandardWebhooksVerifier(Fixture.Secret, FixtureAgnosticTolerance);

        var result = verifier.Verify(Encoding.UTF8.GetBytes(Fixture.Payload), ValidHeaders());

        Assert.True(result.IsValid);
    }
}
