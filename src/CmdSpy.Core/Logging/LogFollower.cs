using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using CmdSpy.Core.Models;

namespace CmdSpy.Core.Logging;

/// <summary>
/// Follows the JSON-lines log that another CMD-spy instance — normally the
/// boot-start background service — is writing, and replays it as a live
/// <see cref="ICaptureFeed"/>. This lets the GUI show captures (and their
/// analyses) from before anyone logged in, without running a second capture
/// session alongside the service.
/// </summary>
public sealed class LogFollower : ICaptureFeed, IDisposable
{
    private readonly string _directory;
    private readonly TimeSpan _interval;
    private readonly Dictionary<Guid, CmdEvent> _known = new();
    private readonly Queue<Guid> _knownOrder = new();
    private readonly Func<DateTime> _clock;
    private readonly byte[] _readBuffer;
    private readonly byte[] _lineBuffer;
    private readonly int _maxBytesPerPoll;
    private readonly int _maxKnownEvents;
    private Timer? _timer;
    private string? _path;
    private long _position;
    private int _lineLength;
    private bool _discardingOversizedLine;
    private int _busy;

    public LogFollower(string directory, TimeSpan? interval = null, Func<DateTime>? clock = null)
        : this(directory, interval, clock, 64 * 1024, 1024 * 1024, 1024 * 1024 + 3, 10_000)
    {
    }

    internal LogFollower(string directory, TimeSpan? interval, Func<DateTime>? clock,
        int readBufferBytes, int maxBytesPerPoll, int maxLineBytes, int maxKnownEvents)
    {
        _directory = directory;
        _interval = interval ?? TimeSpan.FromMilliseconds(500);
        _clock = clock ?? (() => DateTime.Now);
        _readBuffer = new byte[Math.Max(1, readBufferBytes)];
        _lineBuffer = new byte[Math.Max(1, maxLineBytes)];
        _maxBytesPerPoll = Math.Max(_readBuffer.Length, maxBytesPerPoll);
        _maxKnownEvents = Math.Max(1, maxKnownEvents);
    }

    public event EventHandler<CmdEvent>? EventCaptured;
    public event EventHandler<CmdEvent>? EventUpdated;

    public string Directory => _directory;
    public bool IsRunning => _timer is not null;

    /// <summary>The JSON-lines file for a given day (same naming as <see cref="EventStore"/>).</summary>
    public string PathFor(DateTime day) => Path.Combine(_directory, $"cmdspy-{day:yyyyMMdd}.jsonl");

    /// <summary>
    /// Reads the first bounded chunk already in today's log (returned in capture
    /// order, with no events raised), then incrementally catches up and raises
    /// <see cref="EventCaptured"/> / <see cref="EventUpdated"/> for later chunks.
    /// </summary>
    public IReadOnlyList<CmdEvent> Start()
    {
        var existing = new List<CmdEvent>();
        _path = PathFor(_clock());
        ResetReadState();
        foreach (var ev in ReadNewLines(_path))
        {
            if (_known.TryGetValue(ev.Id, out var known))
            {
                lock (known) known.CopyFrom(ev);
            }
            else
            {
                Remember(ev);
                existing.Add(ev);
                if (existing.Count > _maxKnownEvents) existing.RemoveAt(0);
            }
        }

        _timer ??= new Timer(_ => Poll(), null, _interval, _interval);
        return existing;
    }

    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
    }

    public void Dispose() => Stop();

    /// <summary>Reads any newly completed lines and raises events for them. Safe to call directly (tests).</summary>
    public void Poll()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            var today = PathFor(_clock());
            if (_path is not null && !string.Equals(_path, today, StringComparison.OrdinalIgnoreCase))
            {
                // Midnight: drain what's left of yesterday's file, then switch.
                Dispatch(ReadNewLines(_path));
                if (HasUnreadBytes(_path)) return;
                _path = today;
                ResetReadState();
            }
            _path ??= today;
            Dispatch(ReadNewLines(_path));
        }
        catch
        {
            // A log being rotated or briefly locked — try again next tick.
        }
        finally
        {
            Volatile.Write(ref _busy, 0);
        }
    }

    private void Dispatch(List<CmdEvent> events)
    {
        foreach (var ev in events)
        {
            if (_known.TryGetValue(ev.Id, out var known))
            {
                lock (known) known.CopyFrom(ev);
                EventUpdated?.Invoke(this, known);
            }
            else
            {
                Remember(ev);
                EventCaptured?.Invoke(this, ev);
            }
        }
    }

    private void Remember(CmdEvent ev)
    {
        _known[ev.Id] = ev;
        _knownOrder.Enqueue(ev.Id);
        while (_known.Count > _maxKnownEvents && _knownOrder.TryDequeue(out var oldest))
            _known.Remove(oldest);
    }

    /// <summary>
    /// Parses a bounded byte window added since the last read. Incomplete UTF-8
    /// lines are retained in a fixed-size buffer for the next poll; oversized
    /// lines are discarded through their newline without allocating their tail.
    /// </summary>
    private List<CmdEvent> ReadNewLines(string path)
    {
        var result = new List<CmdEvent>();
        if (!File.Exists(path)) return result;

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (fs.Length < _position) ResetReadState();   // file was replaced
        if (fs.Length == _position) return result;

        fs.Seek(_position, SeekOrigin.Begin);
        int remaining = _maxBytesPerPoll;
        while (remaining > 0)
        {
            int requested = Math.Min(_readBuffer.Length, remaining);
            int n = fs.Read(_readBuffer, 0, requested);
            if (n <= 0) break;
            _position += n;
            remaining -= n;
            ParseChunk(_readBuffer, n, result);
            if (n < requested) break;
        }
        return result;
    }

    private void ParseChunk(byte[] bytes, int count, List<CmdEvent> result)
    {
        int segmentStart = 0;
        for (int i = 0; i < count; i++)
        {
            if (bytes[i] != (byte)'\n') continue;
            AppendLineBytes(bytes, segmentStart, i - segmentStart);
            if (!_discardingOversizedLine)
            {
                var text = Encoding.UTF8.GetString(_lineBuffer, 0, _lineLength);
                var ev = EventStore.ParseLine(text.TrimStart('﻿').TrimEnd('\r'));
                if (ev is not null) result.Add(ev);
            }
            _lineLength = 0;
            _discardingOversizedLine = false;
            segmentStart = i + 1;
        }
        AppendLineBytes(bytes, segmentStart, count - segmentStart);
    }

    private void AppendLineBytes(byte[] bytes, int offset, int count)
    {
        if (count <= 0 || _discardingOversizedLine) return;
        if (count > _lineBuffer.Length - _lineLength)
        {
            _lineLength = 0;
            _discardingOversizedLine = true;
            return;
        }
        Buffer.BlockCopy(bytes, offset, _lineBuffer, _lineLength, count);
        _lineLength += count;
    }

    private bool HasUnreadBytes(string path)
    {
        try { return File.Exists(path) && new FileInfo(path).Length > _position; }
        catch { return true; }
    }

    private void ResetReadState()
    {
        _position = 0;
        _lineLength = 0;
        _discardingOversizedLine = false;
    }
}
