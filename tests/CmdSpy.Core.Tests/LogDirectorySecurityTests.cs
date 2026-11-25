using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using CmdSpy.Core.Logging;
using Xunit;

namespace CmdSpy.Core.Tests;

public sealed class LogDirectorySecurityTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [AdminFact]
    public void MachineStore_CreatesProtectedDirectories()
    {
        Directory.CreateDirectory(_dir.Path);
        var productDirectory = Path.Combine(_dir.Path, "CmdSpy");
        var logDirectory = Path.Combine(productDirectory, "logs");

        LogDirectorySecurity.SecureMachineWide(productDirectory, logDirectory);

        AssertRestricted(FileSystemAclExtensions.GetAccessControl(
                new DirectoryInfo(productDirectory), AccessControlSections.Owner | AccessControlSections.Access),
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);
        AssertRestricted(FileSystemAclExtensions.GetAccessControl(
                new DirectoryInfo(logDirectory), AccessControlSections.Owner | AccessControlSections.Access),
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);
    }

    [AdminFact]
    public void MachineStore_RepairsPermissiveDirectoriesAndExistingFiles()
    {
        var productDirectory = Path.Combine(_dir.Path, "CmdSpy");
        var logDirectory = Path.Combine(productDirectory, "logs");
        var existingLog = Path.Combine(logDirectory, "cmdspy-existing.jsonl");
        Directory.CreateDirectory(logDirectory);
        File.WriteAllText(existingLog, "sensitive telemetry");

        MakePermissive(productDirectory, isDirectory: true);
        MakePermissive(logDirectory, isDirectory: true);
        MakePermissive(existingLog, isDirectory: false);

        LogDirectorySecurity.SecureMachineWide(productDirectory, logDirectory);

        AssertRestricted(FileSystemAclExtensions.GetAccessControl(
                new DirectoryInfo(productDirectory), AccessControlSections.Owner | AccessControlSections.Access),
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);
        AssertRestricted(FileSystemAclExtensions.GetAccessControl(
                new DirectoryInfo(logDirectory), AccessControlSections.Owner | AccessControlSections.Access),
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);
        AssertRestricted(FileSystemAclExtensions.GetAccessControl(
                new FileInfo(existingLog), AccessControlSections.Owner | AccessControlSections.Access),
            InheritanceFlags.None);
    }

    [AdminFact]
    public void MachineStore_RejectsReparsePointBeforeUsingItsTarget()
    {
        var productDirectory = Path.Combine(_dir.Path, "CmdSpy");
        var logDirectory = Path.Combine(productDirectory, "logs");
        var redirectTarget = Path.Combine(_dir.Path, "redirect-target");
        Directory.CreateDirectory(productDirectory);
        Directory.CreateDirectory(redirectTarget);
        Directory.CreateSymbolicLink(logDirectory, redirectTarget);

        var error = Assert.Throws<IOException>(() =>
            LogDirectorySecurity.SecureMachineWide(productDirectory, logDirectory));

        Assert.Contains("reparse point", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(Directory.EnumerateFileSystemEntries(redirectTarget));
    }

    private static void MakePermissive(string path, bool isDirectory)
    {
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        var inheritance = isDirectory
            ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit
            : InheritanceFlags.None;
        FileSystemSecurity security = isDirectory ? new DirectorySecurity() : new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            everyone, FileSystemRights.FullControl, inheritance,
            PropagationFlags.None, AccessControlType.Allow));

        if (isDirectory)
            FileSystemAclExtensions.SetAccessControl(new DirectoryInfo(path), (DirectorySecurity)security);
        else
            FileSystemAclExtensions.SetAccessControl(new FileInfo(path), (FileSecurity)security);
    }

    private static void AssertRestricted(
        FileSystemSecurity security,
        InheritanceFlags expectedInheritance)
    {
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var localSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        Assert.True(security.AreAccessRulesProtected);
        Assert.Equal(administrators, security.GetOwner(typeof(SecurityIdentifier)));

        var rules = security.GetAccessRules(
                includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .OfType<FileSystemAccessRule>()
            .ToArray();
        Assert.Equal(2, rules.Length);
        Assert.All(rules, rule =>
        {
            Assert.False(rule.IsInherited);
            Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
            Assert.Equal(FileSystemRights.FullControl, rule.FileSystemRights);
            Assert.Equal(expectedInheritance, rule.InheritanceFlags);
            Assert.Equal(PropagationFlags.None, rule.PropagationFlags);
            Assert.Contains(rule.IdentityReference, new IdentityReference[] { administrators, localSystem });
        });
    }
}
