namespace CmdSpy.Core.Models;

/// <summary>
/// A single network endpoint/connection owned by a spied process (or one of the
/// processes it launched). Comes from live ETW kernel network events, plus a
/// best-effort snapshot of the Windows IP Helper connection table.
/// </summary>
public sealed class NetworkConnectionInfo
{
    public string Protocol { get; set; } = "";      // TCP / TCPv6 / UDP / UDPv6
    public string LocalAddress { get; set; } = "";
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = "";
    public int RemotePort { get; set; }
    public string State { get; set; } = "";          // TCP state, blank for UDP
    public int OwningPid { get; set; }

    /// <summary>"snapshot" (IP Helper connection table) or "ETW" (live kernel network event).</summary>
    public string? Source { get; set; }

    public System.DateTimeOffset? ObservedAtUtc { get; set; }

    public override string ToString()
    {
        var remote = string.IsNullOrEmpty(RemoteAddress)
            ? ""
            : $" -> {RemoteAddress}:{RemotePort}";
        var state = string.IsNullOrEmpty(State) ? "" : $" [{State}]";
        return $"{Protocol} {LocalAddress}:{LocalPort}{remote}{state}";
    }
}
