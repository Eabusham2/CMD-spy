using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace CmdSpy.Core.Logging;

/// <summary>
/// Establishes the security boundary around the default machine-wide telemetry
/// store before any event or service-status file is opened.
/// </summary>
internal static class LogDirectorySecurity
{
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;

    private static readonly SecurityIdentifier Administrators =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    private static readonly SecurityIdentifier LocalSystem =
        new(WellKnownSidType.LocalSystemSid, null);

    /// <summary>
    /// Secures the shared default store. A process without machine-administrator
    /// access keeps the documented reduced-fidelity mode by using its private
    /// profile instead of writing sensitive data into a shared location.
    /// </summary>
    internal static string Prepare(string requestedDirectory)
    {
        if (!OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(requestedDirectory);
            return requestedDirectory;
        }

        var requested = Normalize(requestedDirectory);
        var machineStore = Normalize(CmdSpyOptions.DefaultLogDirectory());
        if (!string.Equals(requested, machineStore, StringComparison.OrdinalIgnoreCase))
        {
            Directory.CreateDirectory(requestedDirectory);
            return requestedDirectory;
        }

        if (!CanProtectMachineStore())
        {
            var userStore = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "CmdSpy", "logs");
            Directory.CreateDirectory(userStore);
            return userStore;
        }

        var productDirectory = Directory.GetParent(machineStore)?.FullName
            ?? throw new InvalidOperationException("The default CMD-spy log directory has no parent.");
        SecureMachineWide(productDirectory, machineStore);
        return machineStore;
    }

    /// <summary>
    /// Repairs both shared directories and every existing telemetry file. Each
    /// target is held without delete/write sharing while its type, ACL and owner
    /// are checked, preventing a path swap during the repair.
    /// </summary>
    internal static void SecureMachineWide(string productDirectory, string logDirectory)
    {
        CreateAndSecureDirectory(productDirectory);
        CreateAndSecureDirectory(logDirectory);

        foreach (var path in Directory.EnumerateFileSystemEntries(logDirectory))
            SecureFile(path);
    }

    private static bool CanProtectMachineStore()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (identity.User?.Equals(LocalSystem) == true)
                return true;
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static string Normalize(string path) =>
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));

    private static void CreateAndSecureDirectory(string path)
    {
        try
        {
            // Inspect an existing final path component before calling
            // CreateDirectory so even a dangling link is rejected, not followed.
            SecureDirectory(path);
        }
        catch (Win32Exception ex) when (
            ex.NativeErrorCode is ErrorFileNotFound or ErrorPathNotFound)
        {
            Directory.CreateDirectory(path);
            SecureDirectory(path);
        }
    }

    private static void SecureDirectory(string path)
    {
        using var handle = OpenWithoutFollowing(path, expectDirectory: true);
        var security = new DirectorySecurity();
        ConfigureSecurity(security, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);
        FileSystemAclExtensions.SetAccessControl(new DirectoryInfo(path), security);

        var actual = FileSystemAclExtensions.GetAccessControl(
            new DirectoryInfo(path), AccessControlSections.Owner | AccessControlSections.Access);
        VerifySecurity(path, actual, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);
    }

    private static void SecureFile(string path)
    {
        using var handle = OpenWithoutFollowing(path, expectDirectory: false);
        var security = new FileSecurity();
        ConfigureSecurity(security, InheritanceFlags.None);
        FileSystemAclExtensions.SetAccessControl(new FileInfo(path), security);

        var actual = FileSystemAclExtensions.GetAccessControl(
            new FileInfo(path), AccessControlSections.Owner | AccessControlSections.Access);
        VerifySecurity(path, actual, InheritanceFlags.None);
    }

    private static void ConfigureSecurity(FileSystemSecurity security, InheritanceFlags inheritance)
    {
        security.SetOwner(Administrators);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            LocalSystem, FileSystemRights.FullControl, inheritance,
            PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            Administrators, FileSystemRights.FullControl, inheritance,
            PropagationFlags.None, AccessControlType.Allow));
    }

    private static void VerifySecurity(
        string path,
        FileSystemSecurity security,
        InheritanceFlags expectedInheritance)
    {
        if (!security.AreAccessRulesProtected ||
            security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner ||
            !owner.Equals(Administrators))
        {
            throw new UnauthorizedAccessException($"CMD-spy could not establish protected ownership on '{path}'.");
        }

        var rules = security.GetAccessRules(
                includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .OfType<FileSystemAccessRule>()
            .ToArray();

        if (rules.Length != 2 ||
            !HasOnlyFullControlRule(rules, LocalSystem, expectedInheritance) ||
            !HasOnlyFullControlRule(rules, Administrators, expectedInheritance))
        {
            throw new UnauthorizedAccessException($"CMD-spy could not establish its restricted ACL on '{path}'.");
        }
    }

    private static bool HasOnlyFullControlRule(
        FileSystemAccessRule[] rules,
        SecurityIdentifier identity,
        InheritanceFlags expectedInheritance) =>
        rules.Count(rule =>
            rule.IdentityReference.Equals(identity) &&
            !rule.IsInherited &&
            rule.AccessControlType == AccessControlType.Allow &&
            rule.FileSystemRights == FileSystemRights.FullControl &&
            rule.InheritanceFlags == expectedInheritance &&
            rule.PropagationFlags == PropagationFlags.None) == 1;

    private static SafeFileHandle OpenWithoutFollowing(string path, bool expectDirectory)
    {
        var flags = FileFlagOpenReparsePoint |
            (expectDirectory ? FileFlagBackupSemantics : 0u);
        var handle = CreateFile(
            path,
            FileReadAttributes,
            FileShare.Read,
            IntPtr.Zero,
            FileMode.Open,
            flags,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, $"CMD-spy could not safely open '{path}'.");
        }

        try
        {
            if (!GetFileInformationByHandle(handle, out var information))
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"CMD-spy could not inspect '{path}'.");

            if ((information.FileAttributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException($"CMD-spy refuses to use reparse point '{path}' for telemetry.");

            var isDirectory = (information.FileAttributes & FileAttributes.Directory) != 0;
            if (isDirectory != expectDirectory)
                throw new IOException($"CMD-spy found an unexpected file-system object at '{path}'.");

            if (!expectDirectory && information.NumberOfLinks != 1)
                throw new IOException($"CMD-spy refuses to use hard-linked telemetry file '{path}'.");

            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        FileShare shareMode,
        IntPtr securityAttributes,
        FileMode creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation fileInformation);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public FileAttributes FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }
}
