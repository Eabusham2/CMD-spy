using System;
using System.IO;
using System.Security.Cryptography;
using CmdSpy.Core.Monitoring;
using Xunit;

namespace CmdSpy.Core.Tests;

public sealed class SignatureVerifierTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly string _path;
    private readonly DateTime _originalWriteTime;
    private static readonly byte[] Original = { 1, 2, 3, 4 };
    private static readonly byte[] Replacement = { 5, 6, 7, 8 };

    public SignatureVerifierTests()
    {
        Directory.CreateDirectory(_dir.Path);
        _path = Path.Combine(_dir.Path, "replace.bin");
        File.WriteAllBytes(_path, Original);
        _originalWriteTime = File.GetLastWriteTimeUtc(_path);
    }

    public void Dispose() => _dir.Dispose();

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MetadataPreservingReplacementUsesTheSelectedMode(bool alwaysRecheck)
    {
        var verifier = new SignatureVerifier();
        Assert.False(verifier.AlwaysRecheck);
        verifier.AlwaysRecheck = alwaysRecheck;
        var original = verifier.Verify(_path, "original");

        ReplacePreservingMetadata(Replacement);
        var replacement = verifier.Verify(_path, "replacement");

        Assert.Equal(original.FileSize, replacement.FileSize);
        Assert.Equal(Hash(Original), original.Sha256);
        Assert.Equal(Hash(alwaysRecheck ? Replacement : Original), replacement.Sha256);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DefaultCacheInvalidatesWhenTimestampOrSizeChanges(bool changeSize)
    {
        var verifier = new SignatureVerifier();
        verifier.Verify(_path, "original");
        var bytes = changeSize ? new byte[] { 5, 6, 7, 8, 9 } : Replacement;
        File.WriteAllBytes(_path, bytes);
        File.SetLastWriteTimeUtc(_path, changeSize ? _originalWriteTime : _originalWriteTime.AddSeconds(2));

        Assert.Equal(Hash(bytes), verifier.Verify(_path, "changed").Sha256);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SwitchingOnThenOffCannotRestorePreviousCachedResults(bool verifyWhileEnabled)
    {
        var verifier = new SignatureVerifier();
        verifier.Verify(_path, "original");
        ReplacePreservingMetadata(Replacement);

        verifier.AlwaysRecheck = true;
        if (verifyWhileEnabled)
            Assert.Equal(Hash(Replacement), verifier.Verify(_path, "fresh").Sha256);
        verifier.AlwaysRecheck = false;

        Assert.Equal(Hash(Replacement), verifier.Verify(_path, "cached again").Sha256);
        ReplacePreservingMetadata(new byte[] { 9, 10, 11, 12 });
        Assert.Equal(Hash(Replacement), verifier.Verify(_path, "cache restored").Sha256);
    }

    [Fact]
    public void AssigningTheCurrentModeKeepsTheCache()
    {
        var verifier = new SignatureVerifier();
        verifier.Verify(_path, "original");
        ReplacePreservingMetadata(Replacement);
        verifier.AlwaysRecheck = false;

        Assert.Equal(Hash(Original), verifier.Verify(_path, "still cached").Sha256);
    }

    [Fact]
    public void CachedResultsAreIndependentCopiesWithCurrentRoleAndPid()
    {
        var verifier = new SignatureVerifier();
        var first = verifier.Verify(_path, "parent", 10);
        first.Sha256 = "caller changed its copy";
        var second = verifier.Verify(_path, "this process", 20);

        Assert.NotSame(first, second);
        Assert.Equal("parent", first.Role);
        Assert.Equal(10, first.ProcessId);
        Assert.Equal("this process", second.Role);
        Assert.Equal(20, second.ProcessId);
        Assert.Equal(Hash(Original), second.Sha256);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void InvestigatorUsesIndependentFreshAndHashOptions(bool alwaysRecheck, bool computeHashes)
    {
        Assert.False(new CmdSpyOptions().AlwaysRecheckFileSignatures);
        var options = new CmdSpyOptions
        {
            AlwaysRecheckFileSignatures = alwaysRecheck,
            ComputeFileHashes = computeHashes
        };
        using var investigator = new Investigator(new ProcessCache(), options);
        var verifier = investigator.Signatures;

        Assert.Equal(alwaysRecheck, verifier.AlwaysRecheck);
        Assert.Equal(computeHashes, verifier.ComputeHashes);
        Assert.Equal(computeHashes ? Hash(Original) : null, verifier.Verify(_path, "before toggle").Sha256);

        verifier.AlwaysRecheck = !alwaysRecheck;
        ReplacePreservingMetadata(Replacement);
        Assert.Equal(computeHashes ? Hash(Replacement) : null, verifier.Verify(_path, "after toggle").Sha256);
    }

    private void ReplacePreservingMetadata(byte[] bytes)
    {
        File.WriteAllBytes(_path, bytes);
        File.SetLastWriteTimeUtc(_path, _originalWriteTime);
        Assert.Equal(Original.Length, new FileInfo(_path).Length);
        Assert.Equal(_originalWriteTime, File.GetLastWriteTimeUtc(_path));
    }

    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));
}
