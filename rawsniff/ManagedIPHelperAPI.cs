using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace rawsniff
{
    public static class ManagedIPHelperAPI
    {

        public static int getPIDTCP(string src_ip, int src_port, string dest_ip, int dst_port)
        {
            foreach (TcpRow tcpRow in ManagedIpHelper.GetExtendedTcpTable(true))
            {
                // SO...  we're dealing with local/remote address:port pairs in the ManagedIPHelperAPI but we are dealing with
                // source/destination pairs in the raw socket portion - so we have to handle either set.
                if ((tcpRow.LocalEndPoint.Address.ToString() == src_ip && tcpRow.LocalEndPoint.Port == src_port &&
                      tcpRow.RemoteEndPoint.Address.ToString() == dest_ip && tcpRow.RemoteEndPoint.Port == dst_port) ||
                     (tcpRow.RemoteEndPoint.Address.ToString() == src_ip && tcpRow.RemoteEndPoint.Port == src_port &&
                      tcpRow.LocalEndPoint.Address.ToString() == dest_ip && tcpRow.LocalEndPoint.Port == dst_port)
                    )
                {
                    return tcpRow.ProcessId;
                }
            }

            return 0;
        }

        public static int getPIDUDP(string src_ip, int src_port, string dst_ip, int dst_port)
        {
            foreach (UdpRow udpRow in ManagedIpHelper.GetExtendedUdpTable(true))
            {
                //Console.WriteLine("{0}:{1}->{2}:{3} vs {4}:{5}", src_ip, src_port, dst_ip, dst_port, udpRow.LocalEndPoint.Address, udpRow.LocalEndPoint.Port);
                // SO...  we're dealing with local/remote address:port pairs in the ManagedIPHelperAPI but we are dealing with
                // source/destination pairs in the raw socket portion - so we have to handle either set.
                if ((udpRow.LocalEndPoint.Address.ToString() == src_ip && udpRow.LocalEndPoint.Port == src_port) ||
                     (udpRow.LocalEndPoint.Address.ToString() == dst_ip && udpRow.LocalEndPoint.Port == dst_port)
                    )
                {
                    return udpRow.ProcessId;

                }
            }
            return 0;
        }

        public static string getProcessNameTCP(string src_ip, int src_port, string dest_ip, int dst_port)
        {
            foreach (TcpRow tcpRow in ManagedIpHelper.GetExtendedTcpTable(true))
            {
                // SO...  we're dealing with local/remote address:port pairs in the ManagedIPHelperAPI but we are dealing with
                // source/destination pairs in the raw socket portion - so we have to handle either set.
                if ((tcpRow.LocalEndPoint.Address.ToString() == src_ip && tcpRow.LocalEndPoint.Port == src_port &&
                      tcpRow.RemoteEndPoint.Address.ToString() == dest_ip && tcpRow.RemoteEndPoint.Port == dst_port) ||
                     (tcpRow.RemoteEndPoint.Address.ToString() == src_ip && tcpRow.RemoteEndPoint.Port == src_port &&
                      tcpRow.LocalEndPoint.Address.ToString() == dest_ip && tcpRow.LocalEndPoint.Port == dst_port)
                    )
                {
                    string p = "";
                    try
                    {
                        p = Process.GetProcessById(tcpRow.ProcessId).ProcessName;
                    }
                    catch
                    {
                        p = "pid:" + Convert.ToInt32(tcpRow.ProcessId);
                    }
                    return p;
                }
            }

            return "";
        }

        public static string getProcessNameUDP(string src_ip, int src_port, string dst_ip, int dst_port)
        {
            foreach (UdpRow udpRow in ManagedIpHelper.GetExtendedUdpTable(true))
            {
                // SO...  we're dealing with local/remote address:port pairs in the ManagedIPHelperAPI but we are dealing with
                // source/destination pairs in the raw socket portion - so we have to handle either set.
                if ((udpRow.LocalEndPoint.Address.ToString() == src_ip && udpRow.LocalEndPoint.Port == src_port) ||
                     (udpRow.LocalEndPoint.Address.ToString() == dst_ip && udpRow.LocalEndPoint.Port == dst_port)
                    )
                {
                    string p = "";
                    try
                    {
                        p = Process.GetProcessById(udpRow.ProcessId).ProcessName;
                    }
                    catch
                    {
                        p = "pid:" + Convert.ToInt32(udpRow.ProcessId);
                    }
                    return p;

                }
            }
            return "";
        }

        public static bool matchProcessTCP(int PID, string src_ip, int src_port, string dest_ip, int dst_port)
        {
            foreach (TcpRow tcpRow in ManagedIpHelper.GetExtendedTcpTable(true))
            {                
                // SO...  we're dealing with local/remote address:port pairs in the ManagedIPHelperAPI but we are dealing with
                // source/destination pairs in the raw socket portion - so we have to handle either set.
                if ( (tcpRow.LocalEndPoint.Address.ToString() == src_ip && tcpRow.LocalEndPoint.Port == src_port &&
                      tcpRow.RemoteEndPoint.Address.ToString() == dest_ip && tcpRow.RemoteEndPoint.Port == dst_port) ||
                     (tcpRow.RemoteEndPoint.Address.ToString() == src_ip && tcpRow.RemoteEndPoint.Port == src_port &&
                      tcpRow.LocalEndPoint.Address.ToString() == dest_ip && tcpRow.LocalEndPoint.Port == dst_port)
                    )
                {
                    if (tcpRow.ProcessId == PID)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        public static bool matchProcessTCP(string ProcessName, string src_ip, int src_port, string dest_ip, int dst_port)
        {
            foreach (TcpRow tcpRow in ManagedIpHelper.GetExtendedTcpTable(true))
            {
                // SO...  we're dealing with local/remote address:port pairs in the ManagedIPHelperAPI but we are dealing with
                // source/destination pairs in the raw socket portion - so we have to handle either set.
                if ((tcpRow.LocalEndPoint.Address.ToString() == src_ip && tcpRow.LocalEndPoint.Port == src_port &&
                      tcpRow.RemoteEndPoint.Address.ToString() == dest_ip && tcpRow.RemoteEndPoint.Port == dst_port) ||
                     (tcpRow.RemoteEndPoint.Address.ToString() == src_ip && tcpRow.RemoteEndPoint.Port == src_port &&
                      tcpRow.LocalEndPoint.Address.ToString() == dest_ip && tcpRow.LocalEndPoint.Port == dst_port)
                    )
                {
                    if (Process.GetProcessById(tcpRow.ProcessId).ProcessName == ProcessName)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        public static bool matchProcessUDP(int PID, string src_ip, int src_port, string dst_ip, int dst_port)
        {
            foreach (UdpRow udpRow in ManagedIpHelper.GetExtendedUdpTable(true))
            {
                // SO...  we're dealing with local/remote address:port pairs in the ManagedIPHelperAPI but we are dealing with
                // source/destination pairs in the raw socket portion - so we have to handle either set.
                if ((udpRow.LocalEndPoint.Address.ToString() == src_ip && udpRow.LocalEndPoint.Port == src_port) ||
                     (udpRow.LocalEndPoint.Address.ToString() == dst_ip && udpRow.LocalEndPoint.Port == dst_port)
                    )
                {
                    if (udpRow.ProcessId == PID)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        public static bool matchProcessUDP(string ProcessName, string src_ip, int src_port, string dst_ip, int dst_port)
        {
            foreach (UdpRow udpRow in ManagedIpHelper.GetExtendedUdpTable(true))
            {
                // SO...  we're dealing with local/remote address:port pairs in the ManagedIPHelperAPI but we are dealing with
                // source/destination pairs in the raw socket portion - so we have to handle either set.
                if ((udpRow.LocalEndPoint.Address.ToString() == src_ip && udpRow.LocalEndPoint.Port == src_port) ||
                     (udpRow.LocalEndPoint.Address.ToString() == dst_ip && udpRow.LocalEndPoint.Port == dst_port)
                    )
                {
                    try
                    {
                        if (Process.GetProcessById(udpRow.ProcessId).ProcessName == ProcessName)
                        {
                            return true;
                        }
                    } catch {
                        // this is here because of possible crash if process is no longer extant by the time we loop through here...
                        return false;
                    }
                }
            }

            return false;
        }
    }

    // Managed IP Helper API from Tim Van Wassenhove
    // http://timvw.be/2007/09/09/build-your-own-netstatexe-with-c/

    #region Managed IP Helper API

    public class TcpTable : IEnumerable<TcpRow>
    {
        #region Private Fields

        private IEnumerable<TcpRow> tcpRows;

        #endregion

        #region Constructors

        public TcpTable(IEnumerable<TcpRow> tcpRows)
        {
            this.tcpRows = tcpRows;
        }

        #endregion

        #region Public Properties

        public IEnumerable<TcpRow> Rows
        {
            get { return this.tcpRows; }
        }

        #endregion

        #region IEnumerable<TcpRow> Members

        public IEnumerator<TcpRow> GetEnumerator()
        {
            return this.tcpRows.GetEnumerator();
        }

        #endregion

        #region IEnumerable Members

        IEnumerator IEnumerable.GetEnumerator()
        {
            return this.tcpRows.GetEnumerator();
        }

        #endregion
    }

    public class TcpRow
    {
        #region Private Fields

        private IPEndPoint localEndPoint;
        private IPEndPoint remoteEndPoint;
        private TcpState state;
        private int processId;

        #endregion

        #region Constructors

        public TcpRow(IpHelper.TcpRow tcpRow)
        {
            this.state = tcpRow.state;
            this.processId = tcpRow.owningPid;

            int localPort = (tcpRow.localPort1 << 8) + (tcpRow.localPort2) + (tcpRow.localPort3 << 24) + (tcpRow.localPort4 << 16);
            long localAddress = tcpRow.localAddr;
            this.localEndPoint = new IPEndPoint(localAddress, localPort);

            int remotePort = (tcpRow.remotePort1 << 8) + (tcpRow.remotePort2) + (tcpRow.remotePort3 << 24) + (tcpRow.remotePort4 << 16);
            long remoteAddress = tcpRow.remoteAddr;
            this.remoteEndPoint = new IPEndPoint(remoteAddress, remotePort);
        }

        #endregion

        #region Public Properties

        public IPEndPoint LocalEndPoint
        {
            get { return this.localEndPoint; }
        }

        public IPEndPoint RemoteEndPoint
        {
            get { return this.remoteEndPoint; }
        }

        public TcpState State
        {
            get { return this.state; }
        }

        public int ProcessId
        {
            get { return this.processId; }
        }

        #endregion
    }


    public class UdpTable : IEnumerable<UdpRow>
    {
        #region Private Fields

        private IEnumerable<UdpRow> udpRows;

        #endregion

        #region Constructors

        public UdpTable(IEnumerable<UdpRow> udpRows)
        {
            this.udpRows = udpRows;
        }

        #endregion

        #region Public Properties

        public IEnumerable<UdpRow> Rows
        {
            get { return this.udpRows; }
        }

        #endregion

        #region IEnumerable<UdpRow> Members

        public IEnumerator<UdpRow> GetEnumerator()
        {
            return this.udpRows.GetEnumerator();
        }

        #endregion

        #region IEnumerable Members

        IEnumerator IEnumerable.GetEnumerator()
        {
            return this.udpRows.GetEnumerator();
        }

        #endregion
    }

    public class UdpRow
    {
        #region Private Fields

        private IPEndPoint localEndPoint;
        private int processId;

        #endregion

        #region Constructors

        public UdpRow(IpHelper.UdpRow udpRow)
        {
            //this.state = udpRow.state;
            this.processId = udpRow.owningPid;

            int localPort = (udpRow.localPort1 << 8) + (udpRow.localPort2) + (udpRow.localPort3 << 24) + (udpRow.localPort4 << 16);
            long localAddress = udpRow.localAddr;
            this.localEndPoint = new IPEndPoint(localAddress, localPort);

            //int remotePort = (udpRow.remotePort1 << 8) + (udpRow.remotePort2) + (udpRow.remotePort3 << 24) + (udpRow.remotePort4 << 16);
            //long remoteAddress = udpRow.remoteAddr;
            //this.remoteEndPoint = new IPEndPoint(remoteAddress, remotePort);
        }

        #endregion

        #region Public Properties

        public IPEndPoint LocalEndPoint
        {
            get { return this.localEndPoint; }
        }

        //public IPEndPoint RemoteEndPoint
        //{
        //    get { return this.remoteEndPoint; }
        //}

        public int ProcessId
        {
            get { return this.processId; }
        }

        #endregion
    }

    public static class ManagedIpHelper
    {
        #region Public Methods

        public static TcpTable GetExtendedTcpTable(bool sorted)
        {
            List<TcpRow> tcpRows = new List<TcpRow>();

            IntPtr tcpTable = IntPtr.Zero;
            int tcpTableLength = 0;

            if (IpHelper.GetExtendedTcpTable(tcpTable, ref tcpTableLength, sorted, IpHelper.AfInet, IpHelper.TcpTableType.OwnerPidAll, 0) != 0)
            {
                try
                {
                    tcpTable = Marshal.AllocHGlobal(tcpTableLength);
                    if (IpHelper.GetExtendedTcpTable(tcpTable, ref tcpTableLength, true, IpHelper.AfInet, IpHelper.TcpTableType.OwnerPidAll, 0) == 0)
                    {
                        IpHelper.TcpTable table = (IpHelper.TcpTable)Marshal.PtrToStructure(tcpTable, typeof(IpHelper.TcpTable));

                        IntPtr rowPtr = (IntPtr)((long)tcpTable + Marshal.SizeOf(table.length));
                        for (int i = 0; i < table.length; ++i)
                        {
                            tcpRows.Add(new TcpRow((IpHelper.TcpRow)Marshal.PtrToStructure(rowPtr, typeof(IpHelper.TcpRow))));
                            rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(typeof(IpHelper.TcpRow)));
                        }
                    }
                }
                finally
                {
                    if (tcpTable != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(tcpTable);
                    }
                }
            }

            return new TcpTable(tcpRows);
        }


        public static UdpTable GetExtendedUdpTable(bool sorted)
        {
            List<UdpRow> udpRows = new List<UdpRow>();

            IntPtr udpTable = IntPtr.Zero;
            int udpTableLength = 0;

            if (IpHelper.GetExtendedUdpTable(udpTable, ref udpTableLength, sorted, IpHelper.AfInet, IpHelper.UdpTableType.OwnerPid, 0) != 0)
            {
                try
                {
                    udpTable = Marshal.AllocHGlobal(udpTableLength);
                    if (IpHelper.GetExtendedUdpTable(udpTable, ref udpTableLength, true, IpHelper.AfInet, IpHelper.UdpTableType.OwnerPid, 0) == 0)
                    {
                        IpHelper.UdpTable table = (IpHelper.UdpTable)Marshal.PtrToStructure(udpTable, typeof(IpHelper.UdpTable));

                        IntPtr rowPtr = (IntPtr)((long)udpTable + Marshal.SizeOf(table.length));
                        for (int i = 0; i < table.length; ++i)
                        {
                            udpRows.Add(new UdpRow((IpHelper.UdpRow)Marshal.PtrToStructure(rowPtr, typeof(IpHelper.UdpRow))));
                            rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(typeof(IpHelper.UdpRow)));
                        }
                    }
                }
                finally
                {
                    if (udpTable != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(udpTable);
                    }
                }
            }

            return new UdpTable(udpRows);
        }


      
        #endregion
    }

    #endregion

    #region P/Invoke IP Helper API

    /// <summary>
    /// <see cref="http://msdn2.microsoft.com/en-us/library/aa366073.aspx"/>
    /// </summary>
    public static class IpHelper
    {
        #region Public Fields

        public const string DllName = "iphlpapi.dll";
        public const int AfInet = 2;

        #endregion

        #region Public Methods

        /// <summary>
        /// <see cref="http://msdn2.microsoft.com/en-us/library/aa365928.aspx"/>
        /// </summary>
        [DllImport(IpHelper.DllName, SetLastError = true)]
        public static extern uint GetExtendedTcpTable(IntPtr tcpTable, ref int tcpTableLength, bool sort, int ipVersion, TcpTableType tcpTableType, int reserved);

        /// <summary>
        /// <see cref="https://msdn.microsoft.com/en-us/library/aa365930(v=vs.85).aspx"/>
        /// </summary>
        [DllImport(IpHelper.DllName, SetLastError = true)]
        public static extern uint GetExtendedUdpTable(IntPtr udpTable, ref int udpTableLength, bool sort, int ipVersion, UdpTableType udpTableType, int reserved);

        #endregion

        #region Public Enums

        /// <summary>
        /// <see cref="http://msdn2.microsoft.com/en-us/library/aa366386.aspx"/>
        /// </summary>
        public enum TcpTableType
        {
            BasicListener,
            BasicConnections,
            BasicAll,
            OwnerPidListener,
            OwnerPidConnections,
            OwnerPidAll,
            OwnerModuleListener,
            OwnerModuleConnections,
            OwnerModuleAll,
        }

        /// <summary>
        /// <see cref="https://msdn.microsoft.com/en-us/library/aa366388(v=vs.85).aspx"/>
        /// </summary>
        public enum UdpTableType
        {
           Basic,
           OwnerPid,
           OwnerModule,
        }

        #endregion

        #region Public Structs

        /// <summary>
        /// <see cref="http://msdn2.microsoft.com/en-us/library/aa366921.aspx"/>
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct TcpTable
        {
            public uint length;
            public TcpRow row;
        }

        /// <summary>
        /// <see cref="https://msdn.microsoft.com/en-us/library/aa366932(v=vs.85).aspx"/>
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct UdpTable
        {
            public uint length;
            public UdpRow row;
        }

        /// <summary>
        /// <see cref="http://msdn2.microsoft.com/en-us/library/aa366913.aspx"/>
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct TcpRow
        {
            public TcpState state;
            public uint localAddr;
            public byte localPort1;
            public byte localPort2;
            public byte localPort3;
            public byte localPort4;
            public uint remoteAddr;
            public byte remotePort1;
            public byte remotePort2;
            public byte remotePort3;
            public byte remotePort4;
            public int owningPid;
        }

        /// <summary>
        /// <see cref="https://msdn.microsoft.com/en-us/library/aa366928(v=vs.85).aspx"/>
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct UdpRow
        {
            public uint localAddr;
            public byte localPort1;
            public byte localPort2;
            public byte localPort3;
            public byte localPort4;
            public int owningPid;
        }

        #endregion
    }

    #endregion

}
