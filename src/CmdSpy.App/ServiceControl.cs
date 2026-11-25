using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32.SafeHandles;

namespace CmdSpy.App;

/// <summary>
/// Installs, starts, stops and removes the CMD-spy boot service.
///
/// The service runs as LocalSystem, so its program must not live in a folder
/// an ordinary user (or malware running as that user) can write to — otherwise
/// replacing CmdSpy.exe would hand them SYSTEM rights. Installing therefore
/// copies CMD-spy into Program Files first and registers that copy.
/// </summary>
internal static class ServiceControl
{
    private const int MaximumInstallFiles = 2_000;
    private const uint GenericRead = 0x80000000;
    private const uint ReadControl = 0x00020000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const int GenericAllAccess = 0x10000000;
    private const int GenericWriteAccess = 0x40000000;

    private const FileSystemRights MutableRights =
        FileSystemRights.WriteData |
        FileSystemRights.AppendData |
        FileSystemRights.WriteExtendedAttributes |
        FileSystemRights.WriteAttributes |
        FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.Delete |
        FileSystemRights.ChangePermissions |
        FileSystemRights.TakeOwnership;

    private const int MutableAccessMask =
        (int)MutableRights | GenericAllAccess | GenericWriteAccess;

    private static readonly SecurityIdentifier AdministratorsSid =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier LocalSystemSid =
        new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier BuiltinUsersSid =
        new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly SecurityIdentifier TrustedInstallerSid =
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
    private static readonly SecurityIdentifier OwnerRightsSid = new("S-1-3-4");
    private static readonly SecurityIdentifier CreatorOwnerSid = new("S-1-3-0");

    public const string ServiceName = "CmdSpy";
    public const string DisplayName = "CMD-spy popup monitor";
    public const string Description =
        "Captures every command-prompt, console and script-host window from boot (before login) and logs its " +
        "command line, cause, launch chain, actions, networking and an evidence-based analysis.";

    public static string InstallDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "CmdSpy");

    public static string StatusLogPath(string logDirectory) => Path.Combine(logDirectory, "cmdspy-service.log");

    /// <summary>Where the installed copy of the running app lives.</summary>
    public static string InstalledAppPath
    {
        get
        {
            var host = Environment.ProcessPath ?? "CmdSpy.exe";
            bool dotnetHost = Path.GetFileNameWithoutExtension(host).Equals("dotnet", StringComparison.OrdinalIgnoreCase);
            return Path.Combine(InstallDirectory, dotnetHost ? "CmdSpy.dll" : Path.GetFileName(host));
        }
    }

    /// <summary>Current state, or null when the service is not installed.</summary>
    public static ServiceControllerStatus? GetStatus()
    {
        try
        {
            using var sc = new ServiceController(ServiceName);
            return sc.Status;
        }
        catch (InvalidOperationException)
        {
            return null;   // not installed
        }
        catch
        {
            return null;
        }
    }

    public static bool IsRunning => GetStatus() == ServiceControllerStatus.Running;

    public static string StatusText => GetStatus() switch
    {
        null => "not installed",
        ServiceControllerStatus.Running => "running",
        ServiceControllerStatus.Stopped => "stopped",
        ServiceControllerStatus.StartPending => "starting",
        ServiceControllerStatus.StopPending => "stopping",
        var other => other.ToString()!.ToLowerInvariant()
    };

    /// <summary>
    /// Copies CMD-spy into Program Files and returns the installed executable,
    /// pausing the boot service while its files are replaced.
    /// </summary>
    public static string InstallFiles(List<string> log)
    {
        var same = string.Equals(Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\'),
            Path.GetFullPath(InstallDirectory).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        bool pause = !same && IsRunning;
        if (pause) StopService(log);
        try
        {
            return CopyToInstallDirectory(log);
        }
        finally
        {
            if (pause)
            {
                try { StartService(log); }
                catch (Exception ex) { log.Add($"Could not restart the boot service: {ex.Message}"); }
            }
        }
    }

    /// <summary>Copies CMD-spy to Program Files, registers the auto-start service and starts it.</summary>
    public static List<string> Install()
    {
        var log = new List<string>();

        if (GetStatus() is not null)
        {
            StopService(log);
        }

        var exe = CopyToInstallDirectory(log);
        var binPath = BuildBinPath(exe);

        var exists = GetStatus() is not null;
        var (code, output) = exists
            ? Sc($"config {ServiceName} binPath= {binPath} start= auto DisplayName= \"{DisplayName}\"")
            : Sc($"create {ServiceName} binPath= {binPath} start= auto DisplayName= \"{DisplayName}\"");
        if (code != 0) throw new InvalidOperationException($"Registering the service failed: {output.Trim()}");
        log.Add(exists ? "✓ Service configuration updated (starts automatically at boot)." : "✓ Service registered (starts automatically at boot, before login).");

        Sc($"description {ServiceName} \"{Description}\"");
        // Restart automatically if it ever crashes.
        Sc($"failure {ServiceName} reset= 86400 actions= restart/5000/restart/5000/restart/30000");
        log.Add("✓ Set to restart automatically if it stops unexpectedly.");

        StartService(log);
        return log;
    }

    public static List<string> Uninstall()
    {
        var log = new List<string>();
        if (GetStatus() is null)
        {
            log.Add("The service is not installed.");
            return log;
        }
        StopService(log);
        var (code, output) = Sc($"delete {ServiceName}");
        if (code != 0) throw new InvalidOperationException($"Removing the service failed: {output.Trim()}");
        log.Add("✓ Service removed. Log files are kept.");

        // Remove the installed copy, unless this GUI is running from it.
        try
        {
            var here = Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\');
            var installed = Path.GetFullPath(InstallDirectory).TrimEnd('\\');
            if (!string.Equals(here, installed, StringComparison.OrdinalIgnoreCase) && Directory.Exists(installed))
            {
                Directory.Delete(installed, recursive: true);
                log.Add($"✓ Removed {installed}.");
            }
        }
        catch (Exception ex)
        {
            log.Add($"Could not remove the installed files: {ex.Message}");
        }
        return log;
    }

    public static void StartService(List<string>? log = null)
    {
        using var sc = new ServiceController(ServiceName);
        if (sc.Status != ServiceControllerStatus.Running)
        {
            sc.Start();
            sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(45));
        }
        log?.Add("✓ Service is running.");
    }

    public static void StopService(List<string>? log = null)
    {
        using var sc = new ServiceController(ServiceName);
        if (sc.Status != ServiceControllerStatus.Stopped)
        {
            if (sc.CanStop) sc.Stop();
            sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
        }
        log?.Add("✓ Service stopped.");
    }

    // ------------------------------------------------------------ helpers --

    /// <summary>
    /// Copies an administrator-owned snapshot of the running app into Program
    /// Files and returns the installed executable. A single-file CmdSpy.exe is
    /// copied on its own; a regular build folder (it contains CmdSpy.Core.dll)
    /// is copied as a whole.
    /// </summary>
    private static string CopyToInstallDirectory(List<string> log)
    {
        var source = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppContext.BaseDirectory));
        var target = Path.TrimEndingDirectorySeparator(Path.GetFullPath(InstallDirectory));
        var host = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot locate CmdSpy.exe.");
        var usesDotnetHost = Path.GetFileNameWithoutExtension(host).Equals("dotnet", StringComparison.OrdinalIgnoreCase);
        var appFile = Path.GetFullPath(usesDotnetHost ? Path.Combine(source, "CmdSpy.dll") : host);
        var appFileName = Path.GetFileName(appFile);

        if (string.Equals(source, target, StringComparison.OrdinalIgnoreCase))
        {
            bool installedAsDirectory = File.Exists(Path.Combine(source, "CmdSpy.Core.dll"));
            using var installed = OpenTrustedBundle(source, appFileName, installedAsDirectory);
            EnsureAppFilePresent(installed, appFileName);
            log.Add($"Using the installed copy in {target}.");
            return Path.Combine(target, appFileName);
        }

        if (!string.Equals(Path.GetDirectoryName(appFile), source, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The running CMD-spy executable is outside its application directory.");

        bool copyDirectory = File.Exists(Path.Combine(source, "CmdSpy.Core.dll"));
        using var bundle = OpenTrustedBundle(source, appFileName, copyDirectory);
        EnsureAppFilePresent(bundle, appFileName);
        var manifest = CreateManifest(bundle);

        var staging = target + ".staging-" + Guid.NewGuid().ToString("N");
        var backup = target + ".backup-" + Guid.NewGuid().ToString("N");
        bool oldMoved = false;
        bool stagedAtTarget = false;
        try
        {
            CreateSecureDirectory(staging);
            foreach (var file in bundle.Files)
            {
                var destination = Path.Combine(staging, file.RelativePath);
                CreateSecureDirectoryTree(staging, Path.GetDirectoryName(destination)!);
                file.Stream.Position = 0;
                using var output = CreateSecureFile(destination);
                file.Stream.CopyTo(output);
                output.Flush(flushToDisk: true);
            }

            VerifySourceUnchanged(bundle, manifest);
            VerifyBundle(staging, appFileName, copyDirectory, manifest);

            if (File.Exists(target))
                throw new InvalidOperationException($"The install path {target} is a file, not a directory.");
            if (Directory.Exists(target))
            {
                RejectReparsePoint(target);
                Directory.Move(target, backup);
                oldMoved = true;
            }

            Directory.Move(staging, target);
            stagedAtTarget = true;
            VerifyBundle(target, appFileName, copyDirectory, manifest);
        }
        catch
        {
            if (stagedAtTarget && Directory.Exists(target) && !Directory.Exists(staging))
            {
                Directory.Move(target, staging);
                stagedAtTarget = false;
            }
            if (oldMoved && !Directory.Exists(target))
            {
                Directory.Move(backup, target);
                oldMoved = false;
            }
            throw;
        }
        finally
        {
            if (Directory.Exists(staging))
                Directory.Delete(staging, recursive: true);
        }

        if (oldMoved && Directory.Exists(backup))
        {
            try { Directory.Delete(backup, recursive: true); }
            catch (Exception ex) { log.Add($"Could not remove the previous installed files: {ex.Message}"); }
        }

        log.Add(copyDirectory
            ? $"✓ Copied and verified CMD-spy ({bundle.Files.Count} files) in {target}."
            : $"✓ Copied and verified {appFileName} in {target}.");
        return Path.Combine(target, appFileName);
    }

    private static SourceBundle OpenTrustedBundle(string root, string appFileName, bool copyDirectory)
    {
        var bundle = new SourceBundle();
        try
        {
            bundle.DirectoryHandles.Add(OpenTrustedEntry(root, requireDirectory: true));
            if (!copyDirectory)
            {
                AddTrustedFile(bundle, root, Path.Combine(root, appFileName));
                return bundle;
            }

            var pending = new Queue<string>();
            pending.Enqueue(root);
            while (pending.Count > 0)
            {
                var directory = pending.Dequeue();
                foreach (var entry in Directory.EnumerateFileSystemEntries(directory, "*", new EnumerationOptions
                {
                    AttributesToSkip = 0,
                    IgnoreInaccessible = false,
                    RecurseSubdirectories = false,
                    ReturnSpecialDirectories = false
                }))
                {
                    SafeFileHandle? handle = OpenTrustedEntry(entry, requireDirectory: null);
                    try
                    {
                        if (IsDirectory(handle))
                        {
                            bundle.DirectoryHandles.Add(handle);
                            handle = null;
                            pending.Enqueue(entry);
                            continue;
                        }

                        if (bundle.Files.Count >= MaximumInstallFiles)
                            throw new InvalidOperationException(
                                $"{root} holds more than {MaximumInstallFiles} files — put CMD-spy in its own folder before installing the service.");
                        AddTrustedFile(bundle, root, entry, handle);
                        handle = null;
                    }
                    finally
                    {
                        handle?.Dispose();
                    }
                }
            }

            bundle.Files.Sort((left, right) =>
                StringComparer.OrdinalIgnoreCase.Compare(left.RelativePath, right.RelativePath));
            return bundle;
        }
        catch
        {
            bundle.Dispose();
            throw;
        }
    }

    private static void AddTrustedFile(SourceBundle bundle, string root, string path, SafeFileHandle? handle = null)
    {
        handle ??= OpenTrustedEntry(path, requireDirectory: false);
        try
        {
            var relative = Path.GetRelativePath(root, path);
            if (Path.IsPathRooted(relative) || relative.Equals("..", StringComparison.Ordinal) ||
                relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                throw new InvalidOperationException($"Installation file {path} is outside {root}.");
            if (bundle.Files.Any(file => file.RelativePath.Equals(relative, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException($"Installation source contains duplicate path {relative}.");

            var stream = new FileStream(handle, FileAccess.Read);
            handle = null;
            bundle.Files.Add(new SourceFile(relative, stream));
        }
        finally
        {
            handle?.Dispose();
        }
    }

    private static SafeFileHandle OpenTrustedEntry(string path, bool? requireDirectory)
    {
        var handle = CreateFile(
            path,
            GenericRead | ReadControl,
            FileShare.Read,
            IntPtr.Zero,
            FileMode.Open,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, $"Could not lock installation source {path} for verification.");
        }

        try
        {
            var attributes = GetAttributes(handle, path);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException($"Installation source contains a reparse point: {path}");

            bool isDirectory = (attributes & FileAttributes.Directory) != 0;
            if (requireDirectory.HasValue && requireDirectory.Value != isDirectory)
                throw new InvalidOperationException(requireDirectory.Value
                    ? $"Installation directory does not exist: {path}"
                    : $"Installation file does not exist: {path}");

            EnsureTrustedSecurity(path, isDirectory);
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static void EnsureTrustedSecurity(string path, bool isDirectory)
    {
        FileSystemSecurity security = isDirectory
            ? FileSystemAclExtensions.GetAccessControl(
                new DirectoryInfo(path), AccessControlSections.Owner | AccessControlSections.Access)
            : FileSystemAclExtensions.GetAccessControl(
                new FileInfo(path), AccessControlSections.Owner | AccessControlSections.Access);

        var owner = (SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
        if (!IsTrustedPrivilegedSid(owner))
            throw UnsafeSource(path, $"its owner is {owner.Value}");

        var descriptor = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
        if ((descriptor.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0 ||
            descriptor.DiscretionaryAcl is null)
            throw UnsafeSource(path, "it has no restrictive access-control list");

        foreach (GenericAce genericAce in descriptor.DiscretionaryAcl)
        {
            if (genericAce is not QualifiedAce ace ||
                ace.AceQualifier != AceQualifier.AccessAllowed ||
                (ace.AceFlags & AceFlags.InheritOnly) != 0 ||
                (ace.AccessMask & MutableAccessMask) == 0)
                continue;

            if (!IsTrustedPrivilegedSid(ace.SecurityIdentifier) &&
                !ace.SecurityIdentifier.Equals(OwnerRightsSid) &&
                !ace.SecurityIdentifier.Equals(CreatorOwnerSid))
                throw UnsafeSource(path, $"{ace.SecurityIdentifier.Value} can modify it");
        }
    }

    private static InvalidOperationException UnsafeSource(string path, string reason) => new(
        $"Service installation was refused because {path} is not an administrator-owned source: {reason}. " +
        "Move CMD-spy to a directory owned by SYSTEM, TrustedInstaller, or BUILTIN\\Administrators and try again.");

    private static bool IsTrustedPrivilegedSid(SecurityIdentifier sid) =>
        sid.Equals(AdministratorsSid) || sid.Equals(LocalSystemSid) || sid.Equals(TrustedInstallerSid);

    private static Dictionary<string, byte[]> CreateManifest(SourceBundle bundle)
    {
        var manifest = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in bundle.Files)
            manifest.Add(file.RelativePath, Hash(file.Stream));
        return manifest;
    }

    private static void VerifySourceUnchanged(SourceBundle bundle, IReadOnlyDictionary<string, byte[]> manifest)
    {
        foreach (var file in bundle.Files)
        {
            if (!CryptographicOperations.FixedTimeEquals(manifest[file.RelativePath], Hash(file.Stream)))
                throw new InvalidOperationException($"Installation source changed while copying {file.RelativePath}.");
        }
    }

    private static void VerifyBundle(
        string root,
        string appFileName,
        bool copyDirectory,
        IReadOnlyDictionary<string, byte[]> manifest)
    {
        using var installed = OpenTrustedBundle(root, appFileName, copyDirectory);
        EnsureAppFilePresent(installed, appFileName);
        if (installed.Files.Count != manifest.Count)
            throw new InvalidOperationException($"Installed bundle in {root} does not match the verified source.");

        foreach (var file in installed.Files)
        {
            if (!manifest.TryGetValue(file.RelativePath, out var expected) ||
                !CryptographicOperations.FixedTimeEquals(expected, Hash(file.Stream)))
                throw new InvalidOperationException($"Installed file {file.RelativePath} does not match the verified source.");
        }
    }

    private static void EnsureAppFilePresent(SourceBundle bundle, string appFileName)
    {
        if (!bundle.Files.Any(file => file.RelativePath.Equals(appFileName, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException($"Installation source does not contain {appFileName}.");
    }

    private static byte[] Hash(Stream stream)
    {
        stream.Position = 0;
        var hash = SHA256.HashData(stream);
        stream.Position = 0;
        return hash;
    }

    private static void CreateSecureDirectoryTree(string root, string directory)
    {
        if (string.Equals(root, directory, StringComparison.OrdinalIgnoreCase))
            return;

        var parent = Path.GetDirectoryName(directory)
            ?? throw new InvalidOperationException($"Cannot determine the parent of {directory}.");
        CreateSecureDirectoryTree(root, parent);
        if (!Directory.Exists(directory))
            CreateSecureDirectory(directory);
    }

    private static void CreateSecureDirectory(string path)
    {
        var security = new DirectorySecurity();
        security.SetOwner(AdministratorsSid);
        security.SetGroup(AdministratorsSid);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(
            LocalSystemSid, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            AdministratorsSid, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            BuiltinUsersSid, FileSystemRights.ReadAndExecute, inheritance, PropagationFlags.None, AccessControlType.Allow));
        FileSystemAclExtensions.Create(new DirectoryInfo(path), security);
    }

    private static FileStream CreateSecureFile(string path)
    {
        var security = new FileSecurity();
        security.SetOwner(AdministratorsSid);
        security.SetGroup(AdministratorsSid);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(LocalSystemSid, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(AdministratorsSid, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(BuiltinUsersSid, FileSystemRights.ReadAndExecute, AccessControlType.Allow));
        return FileSystemAclExtensions.Create(
            new FileInfo(path),
            FileMode.CreateNew,
            FileSystemRights.FullControl,
            FileShare.None,
            64 * 1024,
            FileOptions.SequentialScan,
            security);
    }

    private static void RejectReparsePoint(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException($"The install path is a reparse point: {path}");
    }

    private static bool IsDirectory(SafeFileHandle handle) =>
        (GetAttributes(handle, "installation source") & FileAttributes.Directory) != 0;

    private static FileAttributes GetAttributes(SafeFileHandle handle, string path)
    {
        if (!GetFileInformationByHandle(handle, out var information))
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not inspect {path}.");
        return (FileAttributes)information.FileAttributes;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        FileShare shareMode,
        IntPtr securityAttributes,
        FileMode creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
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

    private sealed class SourceFile : IDisposable
    {
        public SourceFile(string relativePath, FileStream stream)
        {
            RelativePath = relativePath;
            Stream = stream;
        }

        public string RelativePath { get; }
        public FileStream Stream { get; }
        public void Dispose() => Stream.Dispose();
    }

    private sealed class SourceBundle : IDisposable
    {
        public List<SourceFile> Files { get; } = new();
        public List<SafeFileHandle> DirectoryHandles { get; } = new();

        public void Dispose()
        {
            foreach (var file in Files)
                file.Dispose();
            foreach (var handle in DirectoryHandles)
                handle.Dispose();
        }
    }

    /// <summary>The service command line: <c>"...\CmdSpy.exe" --service</c> (or via the dotnet host for a .dll build).</summary>
    private static string BuildBinPath(string installedApp)
    {
        string command;
        if (installedApp.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            command = $"\\\"{Environment.ProcessPath}\\\" \\\"{installedApp}\\\" --service";
        else
            command = $"\\\"{installedApp}\\\" --service";
        return $"\"{command}\"";
    }

    private static (int ExitCode, string Output) Sc(string arguments)
    {
        var psi = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "sc.exe"),
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        using var p = Process.Start(psi)!;
        var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit(30_000);
        return (p.ExitCode, output);
    }
}
