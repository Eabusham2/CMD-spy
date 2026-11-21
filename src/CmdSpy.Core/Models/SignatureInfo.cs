using System.Text.Json.Serialization;

namespace CmdSpy.Core.Models;

/// <summary>Authenticode outcomes, written as readable strings in the logs.</summary>
public static class SignatureStatus
{
    /// <summary>Signed, certificate chain trusted, file unmodified since signing.</summary>
    public const string Valid = "Valid";
    public const string Unsigned = "Unsigned";
    /// <summary>A signature exists but does not match the file (modified after signing) or is malformed.</summary>
    public const string Invalid = "Invalid";
    /// <summary>Signature intact but the certificate is not trusted (unknown root, revoked, distrusted).</summary>
    public const string Untrusted = "Untrusted";
    public const string NotFound = "File not found";
    public const string Error = "Error";
    /// <summary>Verification is not possible on this platform.</summary>
    public const string Unavailable = "Unavailable";
}

/// <summary>Who signed an executable, whether the signature holds, and its hash.</summary>
public sealed class SignatureInfo
{
    public string Path { get; set; } = "";

    /// <summary>Why it was checked: "this process", "parent", "launcher", "action", "referenced"...</summary>
    public string Role { get; set; } = "";

    public int? ProcessId { get; set; }

    /// <summary>One of <see cref="SignatureStatus"/>.</summary>
    public string Status { get; set; } = "";

    /// <summary>"Embedded" (signature inside the file) or "Catalog" (Windows system catalog).</summary>
    public string? Kind { get; set; }

    /// <summary>Signer, e.g. "Microsoft Windows" or "ASUSTeK COMPUTER INC.".</summary>
    public string? Publisher { get; set; }
    public string? Issuer { get; set; }
    public string? Thumbprint { get; set; }

    public string? Sha256 { get; set; }
    public long? FileSize { get; set; }

    public string? CompanyName { get; set; }
    public string? ProductName { get; set; }
    public string? FileDescription { get; set; }
    public string? FileVersion { get; set; }
    public string? OriginalFileName { get; set; }

    /// <summary>Extra explanation (error text, WinVerifyTrust result code).</summary>
    public string? Detail { get; set; }

    [JsonIgnore]
    public bool IsValid => Status == SignatureStatus.Valid;

    [JsonIgnore]
    public bool IsMicrosoft =>
        IsValid && Publisher is not null &&
        Publisher.Contains("Microsoft", System.StringComparison.OrdinalIgnoreCase);

    [JsonIgnore]
    public string StatusDisplay => Kind is null ? Status : $"{Status} ({Kind.ToLowerInvariant()})";
}
