using System;
using System.Collections.Generic;
using System.Management;
using CmdSpy.Core.Models;

namespace CmdSpy.Core.Monitoring;

/// <summary>
/// Best-effort enrichment of process metadata via WMI (Win32_Process). Used to
/// resolve a parent process ("cause") and to recover a command line when the
/// primary detector (WMI process-start trace) doesn't supply one.
///
/// Every method degrades gracefully: if the target process has already exited
/// or WMI is unavailable, we return null / empty rather than throwing.
/// </summary>
public static class ProcessSnapshot
{
    public static ProcessInfo? TryGet(int pid)
    {
        if (pid <= 0) return null;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId, SessionId " +
                $"FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementObject mo in searcher.Get())
            {
                using (mo)
                {
                    return new ProcessInfo
                    {
                        ProcessId = pid,
                        ProcessName = mo["Name"] as string ?? "",
                        ImagePath = mo["ExecutablePath"] as string,
                        CommandLine = mo["CommandLine"] as string,
                        ObservedAtUtc = DateTimeOffset.UtcNow
                    };
                }
            }
        }
        catch
        {
            // WMI unavailable or process gone — best effort only.
        }
        return null;
    }

    /// <summary>Resolves the owning user for a process ("DOMAIN\\user").</summary>
    public static (string? user, int sessionId) TryGetOwner(int pid)
    {
        if (pid <= 0) return (null, -1);
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT SessionId FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementObject mo in searcher.Get())
            {
                using (mo)
                {
                    int sessionId = -1;
                    try { sessionId = Convert.ToInt32(mo["SessionId"]); } catch { }

                    string? user = null;
                    try
                    {
                        var args = new object[] { string.Empty, string.Empty };
                        var rc = Convert.ToInt32(mo.InvokeMethod("GetOwner", args));
                        if (rc == 0)
                        {
                            var name = args[0] as string;
                            var domain = args[1] as string;
                            user = string.IsNullOrEmpty(domain) ? name : $"{domain}\\{name}";
                        }
                    }
                    catch { }

                    return (user, sessionId);
                }
            }
        }
        catch
        {
            // best effort
        }
        return (null, -1);
    }

    /// <summary>Lists processes whose parent is <paramref name="parentPid"/>.</summary>
    public static List<ProcessInfo> GetChildren(int parentPid)
    {
        var children = new List<ProcessInfo>();
        if (parentPid <= 0) return children;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, Name, ExecutablePath, CommandLine " +
                $"FROM Win32_Process WHERE ParentProcessId = {parentPid}");
            foreach (ManagementObject mo in searcher.Get())
            {
                using (mo)
                {
                    int pid;
                    try { pid = Convert.ToInt32(mo["ProcessId"]); } catch { continue; }
                    children.Add(new ProcessInfo
                    {
                        ProcessId = pid,
                        ProcessName = mo["Name"] as string ?? "",
                        ImagePath = mo["ExecutablePath"] as string,
                        CommandLine = mo["CommandLine"] as string,
                        ObservedAtUtc = DateTimeOffset.UtcNow
                    });
                }
            }
        }
        catch
        {
            // best effort
        }
        return children;
    }
}
