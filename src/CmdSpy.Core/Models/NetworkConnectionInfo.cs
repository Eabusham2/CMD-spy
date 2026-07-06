namespace CmdSpy.Core.Models;

/// <summary>
/// A single network endpoint/connection owned by a spied process at the moment
/// it was captured. Populated best-effort from the Windows IP Helper API.
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

    public override string ToString()
    {
        var remote = string.IsNullOrEmpty(RemoteAddress)
            ? ""
            : $" -> {RemoteAddress}:{RemotePort}";
        var state = string.IsNullOrEmpty(State) ? "" : $" [{State}]";
        return $"{Protocol} {LocalAddress}:{LocalPort}{remote}{state}";
    }
}
