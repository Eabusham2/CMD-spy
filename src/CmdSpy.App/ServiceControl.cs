using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.ServiceProcess;

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
    public const string ServiceName = "CmdSpy";
    public const string DisplayName = "CMD-spy popup monitor";
    public const string Description =
        "Captures every command-prompt, console and script-host window from boot (before login) and logs its " +
        "command line, cause, launch chain, actions, networking and an evidence-based analysis.";

    public static string InstallDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "CmdSpy");

    public static string StatusLogPath(string logDirectory) => Path.Combine(logDirectory, "cmdspy-service.log");

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
            var files = Directory.GetFiles(source, "*", SearchOption.AllDirectories);
            if (files.Length > 2_000)
                throw new InvalidOperationException(
                    $"{source} holds {files.Length} files — put CMD-spy in its own folder before installing the service.");
            foreach (var file in files)
            {
                var relative = Path.GetRelativePath(source, file);
                var destination = Path.Combine(target, relative);
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.Copy(file, destination, overwrite: true);
            }
            log.Add($"✓ Copied CMD-spy ({files.Length} files) to {target}.");
        }
        else
        {
            File.Copy(appFile, Path.Combine(target, Path.GetFileName(appFile)), overwrite: true);
            log.Add($"✓ Copied {Path.GetFileName(appFile)} to {target}.");
        }
        return Path.Combine(target, Path.GetFileName(appFile));
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
