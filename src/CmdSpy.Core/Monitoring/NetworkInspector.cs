using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using CmdSpy.Core.Models;

namespace CmdSpy.Core.Monitoring;

/// <summary>
/// Snapshots the TCP/UDP tables (via the Windows IP Helper API) and returns the
/// connections owned by a given process id. Everything here is best-effort and
/// never throws: a millisecond-lived cmd window may have no sockets yet, and a
/// non-elevated caller may see a partial table — either way we simply return
/// whatever we can read.
/// </summary>
public static class NetworkInspector
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen,
        bool sort, int ipVersion, int tblClass, int reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen,
        bool sort, int ipVersion, int tblClass, int reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        public uint localPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] remoteAddr;
        public uint remoteScopeId;
        public uint remotePort;
        public uint state;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint localAddr;
        public uint localPort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        public uint localPort;
        public uint owningPid;
    }

    /// <summary>Returns every connection currently owned by <paramref name="pid"/>.</summary>
    public static List<NetworkConnectionInfo> GetConnectionsForPid(int pid)
    {
        var results = new List<NetworkConnectionInfo>();
        try { ReadTcp(AF_INET, pid, results); } catch { /* ignore */ }
        try { ReadTcp(AF_INET6, pid, results); } catch { /* ignore */ }
        try { ReadUdp(AF_INET, pid, results); } catch { /* ignore */ }
        try { ReadUdp(AF_INET6, pid, results); } catch { /* ignore */ }
        return results;
    }

    private static void ReadTcp(int family, int pid, List<NetworkConnectionInfo> results)
    {
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size == 0) return;

        IntPtr table = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(table, ref size, false, family, TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                return;

            int count = Marshal.ReadInt32(table);
            IntPtr row = IntPtr.Add(table, 4);

            if (family == AF_INET)
            {
                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                for (int i = 0; i < count; i++)
                {
                    var r = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(row);
                    row = IntPtr.Add(row, rowSize);
                    if ((int)r.owningPid != pid) continue;
                    results.Add(new NetworkConnectionInfo
                    {
                        Protocol = "TCP",
                        LocalAddress = new IPAddress(r.localAddr).ToString(),
                        LocalPort = NetworkPort(r.localPort),
                        RemoteAddress = new IPAddress(r.remoteAddr).ToString(),
                        RemotePort = NetworkPort(r.remotePort),
                        State = TcpState(r.state),
                        OwningPid = (int)r.owningPid
                    });
                }
            }
            else
            {
                int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();
                for (int i = 0; i < count; i++)
                {
                    var r = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(row);
                    row = IntPtr.Add(row, rowSize);
                    if ((int)r.owningPid != pid) continue;
                    results.Add(new NetworkConnectionInfo
                    {
                        Protocol = "TCPv6",
                        LocalAddress = new IPAddress(r.localAddr, r.localScopeId).ToString(),
                        LocalPort = NetworkPort(r.localPort),
                        RemoteAddress = new IPAddress(r.remoteAddr, r.remoteScopeId).ToString(),
                        RemotePort = NetworkPort(r.remotePort),
                        State = TcpState(r.state),
                        OwningPid = (int)r.owningPid
                    });
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(table);
        }
    }

    private static void ReadUdp(int family, int pid, List<NetworkConnectionInfo> results)
    {
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, false, family, UDP_TABLE_OWNER_PID, 0);
        if (size == 0) return;

        IntPtr table = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedUdpTable(table, ref size, false, family, UDP_TABLE_OWNER_PID, 0) != 0)
                return;

            int count = Marshal.ReadInt32(table);
            IntPtr row = IntPtr.Add(table, 4);

            if (family == AF_INET)
            {
                int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
                for (int i = 0; i < count; i++)
                {
                    var r = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(row);
                    row = IntPtr.Add(row, rowSize);
                    if ((int)r.owningPid != pid) continue;
                    results.Add(new NetworkConnectionInfo
                    {
                        Protocol = "UDP",
                        LocalAddress = new IPAddress(r.localAddr).ToString(),
                        LocalPort = NetworkPort(r.localPort),
                        OwningPid = (int)r.owningPid
                    });
                }
            }
            else
            {
                int rowSize = Marshal.SizeOf<MIB_UDP6ROW_OWNER_PID>();
                for (int i = 0; i < count; i++)
                {
                    var r = Marshal.PtrToStructure<MIB_UDP6ROW_OWNER_PID>(row);
                    row = IntPtr.Add(row, rowSize);
                    if ((int)r.owningPid != pid) continue;
                    results.Add(new NetworkConnectionInfo
                    {
                        Protocol = "UDPv6",
                        LocalAddress = new IPAddress(r.localAddr, r.localScopeId).ToString(),
                        LocalPort = NetworkPort(r.localPort),
                        OwningPid = (int)r.owningPid
                    });
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(table);
        }
    }

    /// <summary>Ports come back in network byte order in the low 16 bits.</summary>
    private static int NetworkPort(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));

    private static string TcpState(uint state) => state switch
    {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => $"STATE_{state}"
    };
}
