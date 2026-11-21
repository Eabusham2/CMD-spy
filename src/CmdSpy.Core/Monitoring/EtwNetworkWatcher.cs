using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using CmdSpy.Core.Models;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace CmdSpy.Core.Monitoring;

/// <summary>
/// Event-based network capture. Opens its own ETW kernel network session
/// (separate from the process session, so heavy network traffic can never
/// cause process events to be dropped) and reports TCP connects/accepts and UDP
/// sends with the owning process ID — including connections made by a process
/// that only lives for a moment, which a connection-table snapshot misses.
/// </summary>
public sealed class EtwNetworkWatcher : IDisposable
{
    public const string DefaultSessionName = "CmdSpy-KernelNetworkSession";

    private readonly string _sessionName;
    private readonly object _udpGate = new();
    private readonly HashSet<(int Pid, string Remote, int Port)> _udpSeen = new();
    private TraceEventSession? _session;
    private Thread? _pumpThread;

    public EtwNetworkWatcher(string? sessionName = null)
    {
        _sessionName = string.IsNullOrWhiteSpace(sessionName) ? DefaultSessionName : sessionName;
    }

    public string Name => "ETW kernel network trace";

    /// <summary>(process ID, connection) for each new connection observed.</summary>
    public event Action<int, NetworkConnectionInfo>? ConnectionObserved;

    public int EventsLost
    {
        get
        {
            try { return _session?.EventsLost ?? 0; }
            catch { return 0; }
        }
    }

    public void Start()
    {
        _session = new TraceEventSession(_sessionName) { StopOnDispose = true };
        _session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);

        var kernel = _session.Source.Kernel;
        kernel.TcpIpConnect += d => Raise(d.ProcessID, "TCP", d.saddr, d.sport, d.daddr, d.dport, "CONNECT", d.TimeStamp);
        kernel.TcpIpConnectIPV6 += d => Raise(d.ProcessID, "TCPv6", d.saddr, d.sport, d.daddr, d.dport, "CONNECT", d.TimeStamp);
        kernel.TcpIpAccept += d => Raise(d.ProcessID, "TCP", d.saddr, d.sport, d.daddr, d.dport, "ACCEPT", d.TimeStamp);
        kernel.TcpIpAcceptIPV6 += d => Raise(d.ProcessID, "TCPv6", d.saddr, d.sport, d.daddr, d.dport, "ACCEPT", d.TimeStamp);
        kernel.UdpIpSend += d => RaiseUdp(d.ProcessID, "UDP", d.saddr, d.sport, d.daddr, d.dport, d.TimeStamp);
        kernel.UdpIpSendIPV6 += d => RaiseUdp(d.ProcessID, "UDPv6", d.saddr, d.sport, d.daddr, d.dport, d.TimeStamp);

        _pumpThread = new Thread(() =>
        {
            try { _session?.Source.Process(); }
            catch { /* session torn down */ }
        })
        {
            IsBackground = true,
            Name = "CmdSpy-ETW-Network"
        };
        _pumpThread.Start();
    }

    private void Raise(int pid, string protocol, IPAddress? local, int localPort, IPAddress? remote, int remotePort,
        string state, DateTime timestamp)
    {
        if (pid <= 4) return;
        var handler = ConnectionObserved;
        if (handler is null) return;
        handler(pid, new NetworkConnectionInfo
        {
            Protocol = protocol,
            LocalAddress = local?.ToString() ?? "",
            LocalPort = localPort,
            RemoteAddress = remote?.ToString() ?? "",
            RemotePort = remotePort,
            State = state,
            OwningPid = pid,
            Source = "ETW",
            ObservedAtUtc = timestamp.ToUniversalTime()
        });
    }

    private void RaiseUdp(int pid, string protocol, IPAddress? local, int localPort, IPAddress? remote, int remotePort, DateTime timestamp)
    {
        if (pid <= 4) return;
        // UDP is chatty: report each (process, destination) once.
        lock (_udpGate)
        {
            if (_udpSeen.Count > 20_000) _udpSeen.Clear();
            if (!_udpSeen.Add((pid, remote?.ToString() ?? "", remotePort))) return;
        }
        Raise(pid, protocol, local, localPort, remote, remotePort, "SEND", timestamp);
    }

    public void Stop()
    {
        try { _session?.Source.StopProcessing(); } catch { }
    }

    public void Dispose()
    {
        Stop();
        try { _session?.Dispose(); } catch { }
        _session = null;
    }
}
