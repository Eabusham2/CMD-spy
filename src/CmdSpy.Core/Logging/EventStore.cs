using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CmdSpy.Core.Formatting;
using CmdSpy.Core.Models;

namespace CmdSpy.Core.Logging;

/// <summary>
/// Persists captured events. Every sighting is written twice:
///   * as a single JSON line to <c>cmdspy-YYYYMMDD.jsonl</c> (machine-readable), and
///   * as a formatted block to <c>cmdspy-YYYYMMDD.log</c> (human-readable),
/// both rolled by date. Writes are serialized so background watcher threads can
/// call in without corrupting the files.
/// </summary>
public sealed class EventStore
{
    private readonly string _directory;
    private readonly object _fileLock = new();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public EventStore(string directory)
    {
        _directory = directory;
        System.IO.Directory.CreateDirectory(_directory);
    }

    public string Directory => _directory;

    public string CurrentJsonlPath =>
        Path.Combine(_directory, $"cmdspy-{DateTime.Now:yyyyMMdd}.jsonl");

    public string CurrentLogPath =>
        Path.Combine(_directory, $"cmdspy-{DateTime.Now:yyyyMMdd}.log");

    /// <summary>Writes the initial creation record for a freshly captured event.</summary>
    public void Append(CmdEvent ev)
    {
        // Serialize/format under lock(ev) — a watcher thread may be attaching a
        // child process to this same event concurrently.
        string json, text;
        lock (ev)
        {
            json = JsonSerializer.Serialize(ev, JsonOptions);
            text = EventTextFormatter.Format(ev);
        }
        lock (_fileLock)
        {
            File.AppendAllText(CurrentJsonlPath, json + Environment.NewLine, Encoding.UTF8);
            File.AppendAllText(CurrentLogPath, text + Environment.NewLine, Encoding.UTF8);
        }
    }

    /// <summary>
    /// Writes a follow-up record once we learn more about an event (the process
    /// exited, spawned a child, or opened a socket). The JSON line is a compact
    /// delta so the original record is never rewritten in place.
    /// </summary>
    public void AppendUpdate(CmdEvent ev, string reason)
    {
        string json;
        lock (ev)
        {
            var delta = new
            {
                update = reason,
                id = ev.Id,
                sequence = ev.SequenceNumber,
                pid = ev.ProcessId,
                exitedAtUtc = ev.ExitedAtUtc,
                lifetimeMs = ev.LifetimeMilliseconds,
                exitCode = ev.ExitCode,
                childCount = ev.ChildProcesses.Count,
                networkCount = ev.NetworkConnections.Count
            };
            json = JsonSerializer.Serialize(delta, JsonOptions);
        }
        lock (_fileLock)
        {
            File.AppendAllText(CurrentJsonlPath, json + Environment.NewLine, Encoding.UTF8);
        }
    }

    /// <summary>Reads back today's JSON-lines file (creation records only).</summary>
    public IEnumerable<CmdEvent> ReadToday()
    {
        var path = CurrentJsonlPath;
        if (!File.Exists(path)) yield break;

        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            CmdEvent? ev = null;
            try
            {
                using var doc = JsonDocument.Parse(line);
                // Skip delta/update records — they lack a ProcessName.
                if (doc.RootElement.TryGetProperty("update", out _)) continue;
                ev = JsonSerializer.Deserialize<CmdEvent>(line, JsonOptions);
            }
            catch
            {
                // Ignore corrupt lines.
            }
            if (ev is not null) yield return ev;
        }
    }
}
