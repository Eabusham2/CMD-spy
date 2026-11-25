using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CmdSpy.Core.Formatting;
using CmdSpy.Core.Models;

namespace CmdSpy.Core.Logging;

/// <summary>
/// Persists captured events to date-rolled files:
///   * <c>cmdspy-YYYYMMDD.jsonl</c> — one JSON object per line (machine-readable).
///     An event is written on creation and again whenever it gains detail (a
///     child process, a new connection, or its exit), so a reader that keeps the
///     last line per event id has the complete, final record.
///   * <c>cmdspy-YYYYMMDD.log</c> — human-readable blocks: one when the popup is
///     first seen and a finalized block when it exits (after its investigation
///     has finished, so the block carries the full analysis).
/// Writes are serialized so background watcher threads can call in without
/// corrupting the files. Files are opened with shared read/write access, so the
/// GUI can follow a log that the background service is writing and the files
/// can be opened in an editor while monitoring runs.
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
        _directory = LogDirectorySecurity.Prepare(directory);
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
            AppendShared(CurrentJsonlPath, json + Environment.NewLine);
            AppendShared(CurrentLogPath, text + Environment.NewLine);
        }
    }

    /// <summary>
    /// Writes an updated snapshot once we learn more about an event (it exited,
    /// spawned a child, or opened a socket). The full event — including the
    /// child-process and network lists — is re-serialized, so a reader that keeps
    /// the last line per event id ends up with the complete, final record rather
    /// than losing the actions/endpoints captured after creation. On exit we also
    /// append a finalized block to the human-readable log.
    /// </summary>
    public void AppendUpdate(CmdEvent ev, string reason)
    {
        string json;
        string? finalText = null;
        lock (ev)
        {
            json = JsonSerializer.Serialize(ev, JsonOptions);
            if (reason == "exit")
                finalText = EventTextFormatter.Format(ev, finalized: true);
            else if (reason == "reanalysis")
                finalText = EventTextFormatter.Format(ev, EventTextFormatter.ReanalysisTitle);
        }
        lock (_fileLock)
        {
            AppendShared(CurrentJsonlPath, json + Environment.NewLine);
            if (finalText is not null)
                AppendShared(CurrentLogPath, finalText + Environment.NewLine);
        }
    }

    /// <summary>
    /// Appends UTF-8 text while letting other processes read (and write) the
    /// file — e.g. the GUI following the service's log. A new file gets a BOM,
    /// as before, so editors detect the encoding.
    /// </summary>
    private static void AppendShared(string path, string text)
    {
        using var fs = new FileStream(path, FileMode.Append, FileAccess.Write,
            FileShare.ReadWrite | FileShare.Delete);
        if (fs.Length == 0)
        {
            var bom = Encoding.UTF8.GetPreamble();
            fs.Write(bom, 0, bom.Length);
        }
        var bytes = Encoding.UTF8.GetBytes(text);
        fs.Write(bytes, 0, bytes.Length);
    }

    /// <summary>Opens a log for reading without blocking a writer.</summary>
    internal static StreamReader OpenShared(string path) =>
        new(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete),
            Encoding.UTF8, detectEncodingFromByteOrderMarks: true);

    /// <summary>Parses one JSON-lines record; null for blank, corrupt or non-event lines.</summary>
    public static CmdEvent? ParseLine(string? line)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;
        try
        {
            var ev = JsonSerializer.Deserialize<CmdEvent>(line, JsonOptions);
            // A real event always has a process name; skip anything else.
            return ev is null || string.IsNullOrEmpty(ev.ProcessName) ? null : ev;
        }
        catch
        {
            return null;   // ignore corrupt / half-written lines
        }
    }

    /// <summary>
    /// Reads back today's JSON-lines file. Each event may appear on several lines
    /// (creation plus later snapshots); the last line for a given id wins, so the
    /// returned events carry their final child/network/lifetime detail.
    /// </summary>
    public IEnumerable<CmdEvent> ReadToday()
    {
        var path = CurrentJsonlPath;
        if (!File.Exists(path)) return Array.Empty<CmdEvent>();

        var byId = new Dictionary<Guid, CmdEvent>();
        var order = new List<Guid>();

        using var reader = OpenShared(path);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            var ev = ParseLine(line);
            if (ev is null) continue;
            if (!byId.ContainsKey(ev.Id)) order.Add(ev.Id);
            byId[ev.Id] = ev;
        }

        return order.Select(id => byId[id]).ToList();
    }
}
