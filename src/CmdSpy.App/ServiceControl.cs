using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
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
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint VolumeNameNt = 0x2;

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
    /// Copies the running app into Program Files and returns the installed
    /// executable. A single-file CmdSpy.exe is copied on its own; a regular
    /// build folder (it contains CmdSpy.Core.dll) is copied as a whole.
    /// </summary>
    private static string CopyToInstallDirectory(List<string> log)
    {
        var source = Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\');
        var target = Path.GetFullPath(InstallDirectory).TrimEnd('\\');
        var host = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot locate CmdSpy.exe.");
        var usesDotnetHost = Path.GetFileNameWithoutExtension(host).Equals("dotnet", StringComparison.OrdinalIgnoreCase);
        var appFile = usesDotnetHost ? Path.Combine(source, "CmdSpy.dll") : host;

        if (string.Equals(source, target, StringComparison.OrdinalIgnoreCase))
        {
            log.Add($"Using the installed copy in {target}.");
            return Path.Combine(target, Path.GetFileName(appFile));
        }

        Directory.CreateDirectory(target);
        if (File.Exists(Path.Combine(source, "CmdSpy.Core.dll")))
        {
            var files = OpenSourceTree(source);
            try
            {
                foreach (var file in files)
                {
                    var destination = Path.Combine(target, file.RelativePath);
                    Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                    CopyOpenedFile(file.Handle, destination);
                }
            }
            finally
            {
                foreach (var file in files)
                    file.Handle.Dispose();
            }
            log.Add($"✓ Copied CMD-spy ({files.Count} files) to {target}.");
        }
        else
        {
            using var root = LockSourceRoot(source);
            using var appHandle = OpenValidatedSourceEntry(source, appFile, root.Identity, expectDirectory: false);
            CopyOpenedFile(appHandle, Path.Combine(target, Path.GetFileName(appFile)));
            log.Add($"✓ Copied {Path.GetFileName(appFile)} to {target}.");
        }
        return Path.Combine(target, Path.GetFileName(appFile));
    }

    private static List<OpenedSourceFile> OpenSourceTree(string source)
    {
        var files = new List<OpenedSourceFile>();
        try
        {
            using var root = LockSourceRoot(source);
            CollectSourceFiles(source, source, root.Identity, files);
            return files;
        }
        catch
        {
            foreach (var file in files)
                file.Handle.Dispose();
            throw;
        }
    }

    private static void CollectSourceFiles(
        string source,
        string directory,
        SourceRoot root,
        List<OpenedSourceFile> files)
    {
        foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
        {
            var relative = GetSafeRelativePath(source, entry);
            var handle = OpenValidatedSourceEntry(source, entry, root, expectDirectory: null);
            bool keepHandle = false;
            try
            {
                var information = GetHandleInformation(entry, handle);
                if ((information.FileAttributes & FileAttributes.Directory) != 0)
                {
                    // Keeping this non-delete-shared handle open prevents the directory
                    // from being replaced while its children are enumerated.
                    CollectSourceFiles(source, entry, root, files);
                }
                else
                {
                    if (files.Count == MaximumInstallFiles)
                        throw new InvalidOperationException(
                            $"{source} holds more than {MaximumInstallFiles:N0} files — put CMD-spy in its own folder before installing the service.");
                    files.Add(new OpenedSourceFile(relative, handle));
                    keepHandle = true;
                }
            }
            finally
            {
                if (!keepHandle)
                    handle.Dispose();
            }
        }
    }

    private static LockedSourceRoot LockSourceRoot(string source)
    {
        var pathRoot = Path.GetPathRoot(source);
        if (string.IsNullOrEmpty(pathRoot))
            throw new InvalidOperationException($"The installation source is not an absolute path: {source}");

        var handles = new List<SafeFileHandle>();
        try
        {
            var current = pathRoot;
            handles.Add(OpenSourceDirectory(current));
            foreach (var component in source[pathRoot.Length..].Split(
                new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
                StringSplitOptions.RemoveEmptyEntries))
            {
                current = Path.Combine(current, component);
                handles.Add(OpenSourceDirectory(current));
            }

            var sourceHandle = handles[^1];
            var information = GetHandleInformation(source, sourceHandle);
            var identity = new SourceRoot(
                GetFinalPath(source, sourceHandle).TrimEnd('\\'),
                information.VolumeSerialNumber);
            return new LockedSourceRoot(identity, handles);
        }
        catch
        {
            for (var i = handles.Count - 1; i >= 0; i--)
                handles[i].Dispose();
            throw;
        }
    }

    private static SafeFileHandle OpenSourceDirectory(string path)
    {
        var handle = OpenSourceHandle(path);
        try
        {
            var information = GetHandleInformation(path, handle);
            if ((information.FileAttributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException($"The installation source path contains a reparse point: {path}");
            if ((information.FileAttributes & FileAttributes.Directory) == 0)
                throw new InvalidOperationException($"The installation source path is not a directory: {path}");
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static SafeFileHandle OpenValidatedSourceEntry(
        string source,
        string path,
        SourceRoot root,
        bool? expectDirectory)
    {
        GetSafeRelativePath(source, path);
        var handle = OpenSourceHandle(path);
        try
        {
            var information = GetHandleInformation(path, handle);
            if ((information.FileAttributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException($"The installation source contains a reparse point: {path}");

            bool isDirectory = (information.FileAttributes & FileAttributes.Directory) != 0;
            if (expectDirectory.HasValue && isDirectory != expectDirectory.Value)
                throw new InvalidOperationException($"The installation source entry changed type while it was being read: {path}");

            var finalPath = GetFinalPath(path, handle);
            if (information.VolumeSerialNumber != root.VolumeSerialNumber || !IsBelowRoot(root.FinalPath, finalPath))
                throw new InvalidOperationException($"The installation source entry resolves outside the source directory: {path}");
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static SafeFileHandle OpenSourceHandle(string path)
    {
        var handle = CreateFile(
            path,
            GenericRead,
            FileShare.Read,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, $"Cannot securely open installation source entry '{path}'.");
        }
        return handle;
    }

    private static ByHandleFileInformation GetHandleInformation(string path, SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var information))
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                $"Cannot inspect installation source entry '{path}'.");
        return information;
    }

    private static string GetFinalPath(string path, SafeFileHandle handle)
    {
        var buffer = new StringBuilder(512);
        while (true)
        {
            var length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, VolumeNameNt);
            if (length == 0)
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    $"Cannot resolve installation source entry '{path}'.");
            if (length < (uint)buffer.Capacity)
                return buffer.ToString();
            buffer.EnsureCapacity(checked((int)length + 1));
            buffer.Clear();
        }
    }

    private static string GetSafeRelativePath(string source, string path)
    {
        var relative = Path.GetRelativePath(source, path);
        if (Path.IsPathRooted(relative) ||
            relative.Equals("..", StringComparison.Ordinal) ||
            relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal) ||
            relative.StartsWith($"..{Path.AltDirectorySeparatorChar}", StringComparison.Ordinal))
            throw new InvalidOperationException($"The installation source entry is outside the source directory: {path}");
        return relative;
    }

    private static bool IsBelowRoot(string root, string path) =>
        path.Length > root.Length &&
        path.StartsWith(root, StringComparison.OrdinalIgnoreCase) &&
        path[root.Length] == '\\';

    private static void CopyOpenedFile(SafeFileHandle source, string destination)
    {
        using var input = new FileStream(source, FileAccess.Read);
        using var output = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None);
        input.CopyTo(output);
    }

    private sealed record OpenedSourceFile(string RelativePath, SafeFileHandle Handle);

    private readonly record struct SourceRoot(string FinalPath, uint VolumeSerialNumber);

    private sealed class LockedSourceRoot : IDisposable
    {
        private readonly List<SafeFileHandle> _handles;

        public LockedSourceRoot(SourceRoot identity, List<SafeFileHandle> handles)
        {
            Identity = identity;
            _handles = handles;
        }

        public SourceRoot Identity { get; }

        public void Dispose()
        {
            for (var i = _handles.Count - 1; i >= 0; i--)
                _handles[i].Dispose();
        }
    }

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

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        FileShare shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        StringBuilder path,
        uint pathLength,
        uint flags);

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
