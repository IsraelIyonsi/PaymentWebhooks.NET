using System.Text;
using PaymentWebhooks.Tests.Support;

namespace PaymentWebhooks.Tests.GitHub;

public class GitHubWebhookVerifierTests
{
    private static readonly GitHubFixture Fixture = FixtureLoader.Load<GitHubFixture>("github-known-answer.json");

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Constructor_RejectsNullOrEmptySecret(string? secret)
    {
        Assert.ThrowsAny<ArgumentException>(() => new GitHubWebhookVerifier(secret!));
    }

    [Fact]
    public void Verify_NullHeaders_ThrowsArgumentNullException()
    {
        var verifier = new GitHubWebhookVerifier(Fixture.Secret);

        Assert.Throws<ArgumentNullException>(
            () => verifier.Verify(Encoding.UTF8.GetBytes(Fixture.Payload), null!));
    }

    public static IEnumerable<object[]> KnownAnswerCases()
    {
        yield return new object[]
        {
            Fixture.Secret,
            Fixture.Payload,
            new Dictionary<string, string> { [GitHubWebhookVerifier.SignatureHeaderName] = Fixture.Signature },
            true,
            WebhookVerificationFailureReason.None,
        };

        yield return new object[]
        {
            Fixture.Secret,
            Fixture.Payload + "-tampered",
            new Dictionary<string, string> { [GitHubWebhookVerifier.SignatureHeaderName] = Fixture.Signature },
            false,
            WebhookVerificationFailureReason.SignatureMismatch,
        };

        yield return new object[]
        {
            "a-completely-different-secret",
            Fixture.Payload,
            new Dictionary<string, string> { [GitHubWebhookVerifier.SignatureHeaderName] = Fixture.Signature },
            false,
            WebhookVerificationFailureReason.SignatureMismatch,
        };

        yield return new object[]
        {
            Fixture.Secret,
            Fixture.Payload,
            new Dictionary<string, string>
            {
                ["x-hub-signature-256"] = Fixture.Signature,
            },
            true,
            WebhookVerificationFailureReason.None,
        };

        yield return new object[]
        {
            Fixture.Secret,
            Fixture.Payload,
            new Dictionary<string, string>(),
            false,
            WebhookVerificationFailureReason.MissingHeader,
        };

        yield return new object[]
        {
            Fixture.Secret,
            Fixture.Payload,
            new Dictionary<string, string>
            {
                [GitHubWebhookVerifier.SignatureHeaderName] = Fixture.Signature.Replace("sha256=", "sha1="),
            },
            false,
            WebhookVerificationFailureReason.MalformedSignatureHeader,
        };

        yield return new object[]
        {
            Fixture.Secret,
            Fixture.Payload,
            new Dictionary<string, string>
            {
                [GitHubWebhookVerifier.SignatureHeaderName] = "not-prefixed-at-all",
            },
            false,
            WebhookVerificationFailureReason.MalformedSignatureHeader,
        };
    }

    [Theory]
    [MemberData(nameof(KnownAnswerCases))]
    public void Verify_KnownAnswerAndEdgeCases_ReturnsExpectedResult(
        string secret,
        string payload,
        Dictionary<string, string> headers,
        bool expectedValid,
        WebhookVerificationFailureReason expectedReason)
    {
        var verifier = new GitHubWebhookVerifier(secret);

        var result = verifier.Verify(Encoding.UTF8.GetBytes(payload), headers);

        Assert.Equal(expectedValid, result.IsValid);
        Assert.Equal(expectedReason, result.FailureReason);
    }

    [Fact]
    public void Verify_UppercaseHexSignature_Succeeds()
    {
        const string prefix = "sha256=";
        var uppercaseSignature = prefix + Fixture.Signature[prefix.Length..].ToUpperInvariant();
        var verifier = new GitHubWebhookVerifier(Fixture.Secret);
        var headers = new Dictionary<string, string>
        {
            [GitHubWebhookVerifier.SignatureHeaderName] = uppercaseSignature,
        };

        var result = verifier.Verify(Encoding.UTF8.GetBytes(Fixture.Payload), headers);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Verify_NonHexCharactersAfterPrefix_FailsAsSignatureMismatchWithoutThrowing()
    {
        var verifier = new GitHubWebhookVerifier(Fixture.Secret);
        var headers = new Dictionary<string, string>
        {
            [GitHubWebhookVerifier.SignatureHeaderName] = "sha256=not-hexadecimal-at-all",
        };

        var result = verifier.Verify(Encoding.UTF8.GetBytes(Fixture.Payload), headers);

        Assert.False(result.IsValid);
        Assert.Equal(WebhookVerificationFailureReason.SignatureMismatch, result.FailureReason);
    }

    [Fact]
    public void Verify_ImplementsIWebhookVerifier()
    {
        IWebhookVerifier verifier = new GitHubWebhookVerifier(Fixture.Secret);
        var headers = new Dictionary<string, string>
        {
            [GitHubWebhookVerifier.SignatureHeaderName] = Fixture.Signature,
        };

        var result = verifier.Verify(Encoding.UTF8.GetBytes(Fixture.Payload), headers);

        Assert.True(result.IsValid);
    }
}
