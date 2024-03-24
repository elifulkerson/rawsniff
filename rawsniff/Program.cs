using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;


namespace rawsniff
{

    class myICMPSegment
    {
        public int type { get; set; }
        public int code { get; set; }
        public long checksum { get; set; }
        public string type_s { get; set; }
        public string code_s { get; set; }
        public int data_position { get; set; }

        public void slurp(byte[] b, int startat) 
        {
            type = (Convert.ToInt32(b[startat + 0]));
            code = (Convert.ToInt32(b[startat + 1]));
            checksum = (Convert.ToInt32(b[startat + 2]) * 256) + Convert.ToInt32(b[startat + 3]);

            data_position = startat + 4;
            
            type_s = "";
            code_s = "";
            
            switch (type)
            {
                case 0:
                    type_s = "Echo Reply";
                    break;
                case 3:
                    type_s = "Destination Unreachable";

                    switch (code)
                    {
                        case 0:
                            code_s = "Net Unreachable";
                            break;
                        case 1:
                            code_s = "Host Unreachable";
                            break;
                        case 2:
                            code_s = "Protocol Unreachable";
                            break;
                        case 3:
                            code_s = "Port Unreachable";
                            break;
                        case 4:
                            code_s = "Fragmentation required and DF set";
                            break;
                        case 5:
                            code_s = "Source Route Failed";
                            break;
                        case 6:
                            code_s = "Destination Network Unknown";
                            break;
                        case 7:
                            code_s = "Destination Host Unknown";
                            break;
                        case 8:
                            code_s = "Source Host Isolated";
                            break;
                        case 9:
                            code_s = "Network Administratively Prohibited";
                            break;
                        case 11:
                            code_s = "Host Administratively Prohibited";
                            break;
                        case 12:
                            code_s = "Host Unreachable for TOS";
                            break;
                        case 13:
                            code_s = "Communication Administratively Prohibited";
                            break;
                    }

                    break;
                case 4:
                    type_s = "Source Quench";
                    break;
                case 5:
                    type_s = "Redirect";
                    switch (code)
                    {
                        case 0:
                            code_s = "Redirect Datagram for the Network";
                            break;
                        case 1:
                            code_s = "Redirect Datagram for the Host";
                            break;
                        case 2:
                            code_s = "Redirect Datagram for the TOS & Network";
                            break;
                        case 3:
                            code_s = "Redirect Datagram for the TOS & Host";
                            break;
                    }
                    break;
                case 8:
                    type_s = "Echo";
                    break;
                case 9:
                    type_s = "Router Advertisement";
                    break;
                case 10:
                    type_s = "Router Selection";
                    break;
                case 11:
                    type_s = "Time Exceeded";

                    switch (code)
                    {
                        case 0:
                            code_s = "TTL Exceeded";
                            break;
                        case 1:
                            code_s = "Fragment Reassembly Time Exceeded";
                            break;
                    }

                    break;
                case 12:
                    type_s = "Parameter Problem";
                    switch (code)
                    {
                        case 0:
                            code_s = "Pointer Problem";
                            break;
                        case 1:
                            code_s = "Missing a Required Operand";
                            break;
                        case 2:
                            code_s = "Bad Length";
                            break;
                    }
                    break;
                case 13:
                    type_s = "Timestamp";
                    break;
                case 14:
                    type_s = "Timestamp Reply";
                    break;
                case 15:
                    type_s = "Information Request";
                    break;
                case 16:
                    type_s = "Information Reply";
                    break;
                case 17:
                    type_s = "Address Mask Request";
                    break;
                case 18:
                    type_s = "Address Mask Reply";
                    break;
                case 30:
                    type_s = "Traceroute";
                    break;

            }


            return;
        }

        public string display(bool brief)
        {
            string buf = " - ICMP Segment Header\n";


            buf += String.Format("   type  : {0} {1}\n", type, type_s);
            buf += String.Format("   code  : {0} {1}\n", code, code_s);
            buf += String.Format(" chksum  : {0}\n", checksum);
        

            buf = buf.Replace("\n", Environment.NewLine);

            return buf;

        }
    }

    class myTCPSegment
    {
        public int src_port { get; set; }
        public int dst_port { get; set; }
        public long seqno { get; set; }
        public long ackno { get; set; }
        public int headerLength { get; set; }
        public int reserved { get; set; }
        public int urg { get; set; }
        public int ack { get; set; }
        public int psh { get; set; }
        public int rst { get; set; }
        public int syn { get; set; }
        public int fin { get; set; }
        public int window_size { get; set; }
        public int tcp_checksum { get; set; }
        public int urgent_pointer { get; set; }
        // meh, options
        // meh, data
        public int data_position { get; set; }

        public void slurp(byte[] b, int startat)
        {
            src_port = (Convert.ToInt32(b[startat + 0]) * 256) + Convert.ToInt32(b[startat + 1]);
            dst_port = (Convert.ToInt32(b[startat + 2]) * 256) + Convert.ToInt32(b[startat + 3]);

            seqno = (Convert.ToUInt32(b[startat + 4]) * 256 * 256 * 256) + (Convert.ToUInt32(b[startat + 5]) * 256 * 256) + (Convert.ToUInt32(b[startat + 6]) * 256) + (Convert.ToUInt32(b[startat + 7]));
            ackno = (Convert.ToUInt32(b[startat + 8]) * 256 * 256 * 256) + (Convert.ToUInt32(b[startat + 9]) * 256 * 256) + (Convert.ToUInt32(b[startat + 10]) * 256) + (Convert.ToUInt32(b[startat + 11]));

            headerLength = Convert.ToInt32(Convert.ToString(Convert.ToInt32(b[startat+12]), 2).PadLeft(8, '0').Substring(0, 4), 2);

            string tmp = Convert.ToString(Convert.ToInt32(b[startat + 13]), 2).PadLeft(8, '0');
            urg = Convert.ToInt32(tmp.Substring(2, 1));
            ack = Convert.ToInt32(tmp.Substring(3, 1));
            psh = Convert.ToInt32(tmp.Substring(4, 1));
            rst = Convert.ToInt32(tmp.Substring(5, 1));
            syn = Convert.ToInt32(tmp.Substring(6, 1));
            fin = Convert.ToInt32(tmp.Substring(7, 1));

            window_size = (Convert.ToInt32(b[startat + 14]) * 256) + Convert.ToInt32(b[startat + 15]);
            tcp_checksum = (Convert.ToInt32(b[startat + 16]) * 256) + Convert.ToInt32(b[startat + 17]);
            urgent_pointer = (Convert.ToInt32(b[startat + 18]) * 256) + Convert.ToInt32(b[startat + 19]);

            data_position = startat + 20;


            return;
        }

        public string flags_s()
        {
            string buf = "";
            if (urg == 1) { buf += "URG "; }
            if (ack == 1) { buf += "ACK "; }
            if (psh == 1) { buf += "PSH "; }
            if (rst == 1) { buf += "RST "; }
            if (syn == 1) { buf += "SYN "; }
            if (fin == 1) { buf += "FIN "; }
            return buf;
        }


        public string display(bool brief)
        {
            string buf = " - TCP Segment Header\n";

            buf += String.Format("   src_port  : {0}\n", src_port);
            buf += String.Format("   dst_port  : {0}\n", dst_port);

            if (!brief)
            {
                buf += String.Format("   seq_no    : {0}\n", seqno);
                buf += String.Format("   ack_no    : {0}\n", ackno);
                buf += String.Format("   length    : {0}\n", headerLength);
            }
            
            buf += String.Format("   flags     : ");
            if (urg == 1) { buf += "URG "; }
            if (ack == 1) { buf += "ACK "; }
            if (psh == 1) { buf += "PSH "; }
            if (rst == 1) { buf += "RST "; }
            if (syn == 1) { buf += "SYN "; }
            if (fin == 1) { buf += "FIN "; }
            buf += "\n";
            
            if (!brief)
            {
                buf += String.Format("   windSize : {0}\n", window_size);
                buf += String.Format("   checksum : {0}\n", tcp_checksum);
                buf += String.Format("   urgPoint : {0}\n", urgent_pointer);
            }
            
            buf = buf.Replace("\n", Environment.NewLine);

            return buf;

        }
    }

    class myUDPSegment
    {
        public int src_port { get; set; }
        public int dst_port { get; set; }
        public int length { get; set; }
        public int udp_checksum { get; set; }
        public int data_position { get; set; }
        // meh, the rest

        public void slurp(byte[] b, int startat)
        {
            src_port = (Convert.ToInt32(b[startat + 0]) * 256) + Convert.ToInt32(b[startat + 1]);
            dst_port = (Convert.ToInt32(b[startat + 2]) * 256) + Convert.ToInt32(b[startat + 3]);

            length = (Convert.ToInt32(b[startat + 4]) * 256) + Convert.ToInt32(b[startat + 5]);
            udp_checksum = (Convert.ToInt32(b[startat + 6]) * 256) + Convert.ToInt32(b[startat + 7]);

            data_position = startat + 8;



        }

        public string display( bool brief)
        {
            string buf = " - UDP Segment Header\n";

            buf += String.Format("   src_port  : {0}\n", src_port);
            buf += String.Format("   dst_port  : {0}\n", dst_port);

            if (!brief)
            {
                buf += String.Format("   length    : {0}\n", length);
                buf += String.Format("   checksum  : {0}\n", udp_checksum);
            }

            buf = buf.Replace("\n", Environment.NewLine);
            return buf;
        }
    }

    class myIPPacket
    {
        public int ip_version { get; set; }
        public int header_len { get; set; }
        public int tos { get; set; }
        public int total_length { get; set; }
        public int fragment_id { get; set; }
        public int r { get; set; }
        public int df { get; set; }
        public int mf { get; set; }
        public int fragment_offset { get; set; }
        public int ttl { get; set; }
        public int protocol { get; set; }
        public string protocol_s { get; set; }
        public int header_checksum { get; set; }
        public long source_ip { get; set; }
        public string source_ip_s { get; set; }
        public long dest_ip { get; set; }
        public string dest_ip_s { get; set; }

        public int data_position { get; set; }
        // options, @@ forget for now don't care for current project


        public void slurp(byte[] b)
        {
            // probably a lot cleaner if I was using proper bit operations, but this is C# and I can't be bothered to learn it properly at the moment.

            ip_version = Convert.ToInt32(Convert.ToString(Convert.ToInt32(b[0]), 2).PadLeft(8, '0').Substring(0, 4), 2);
            header_len = Convert.ToInt32(Convert.ToString(Convert.ToInt32(b[0]), 2).PadLeft(8, '0').Substring(4, 4), 2);
            tos = Convert.ToInt32(b[1]);
            
            total_length = (Convert.ToInt32(b[2]) * 256) + Convert.ToInt32(b[3]);
            fragment_id = (Convert.ToInt32(b[4]) * 256) + Convert.ToInt32(b[5]);

            r = Convert.ToInt32(Convert.ToString(Convert.ToInt32(b[6]), 2).PadLeft(8, '0').Substring(0, 1), 2);
            df = Convert.ToInt32(Convert.ToString(Convert.ToInt32(b[6]), 2).PadLeft(8, '0').Substring(1, 1), 2);
            mf = Convert.ToInt32(Convert.ToString(Convert.ToInt32(b[6]), 2).PadLeft(8, '0').Substring(2, 1), 2);

            string tmp = Convert.ToString(Convert.ToInt32(b[6]), 2).PadLeft(8, '0').Substring(3, 5);
            tmp += Convert.ToString(Convert.ToInt32(b[7]), 2).PadLeft(8, '0');

            fragment_offset = Convert.ToInt32(tmp, 2);

            ttl = Convert.ToInt32(b[8]);
            protocol = Convert.ToInt32(b[9]);
            protocol_s = protocol.ToString();
            if (protocol == 1) { protocol_s = "ICMP"; }
            if (protocol == 2) { protocol_s = "IGMP"; }
            if (protocol == 6) { protocol_s = "TCP"; }
            if (protocol == 17) { protocol_s = "UDP"; }
            if (protocol == 41) { protocol_s = "ENCAP"; }
            // etc, etc etc  http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
            


            header_checksum = (Convert.ToInt32(b[10]) * 256) + Convert.ToInt32(b[11]);

            source_ip = (Convert.ToUInt32(b[12]) * 256 * 256 * 256) + (Convert.ToUInt32(b[13]) * 256 * 256) + (Convert.ToUInt32(b[14]) * 256) + (Convert.ToUInt32(b[15]));
            source_ip_s = Convert.ToUInt32(b[12]).ToString() + "." + Convert.ToUInt32(b[13]).ToString() + "." + Convert.ToUInt32(b[14]).ToString() + "." + Convert.ToUInt32(b[15]).ToString();
            dest_ip = (Convert.ToUInt32(b[16]) * 256 * 256 * 256) + (Convert.ToUInt32(b[17]) * 256 * 256) + (Convert.ToUInt32(b[18]) * 256) + (Convert.ToUInt32(b[19]));
            dest_ip_s = Convert.ToUInt32(b[16]).ToString() + "." + Convert.ToUInt32(b[17]).ToString() + "." + Convert.ToUInt32(b[18]).ToString() + "." + Convert.ToUInt32(b[19]).ToString();


            data_position = 20;


            return;
        }

        public string display(bool brief)
        {
            string buf =         " - IP Packet Header\n";

            if (!brief)
            {
                buf += String.Format("   IPv       : {0}\n", ip_version);
                buf += String.Format("   Header Len: {0}\n", header_len);
                buf += String.Format("   ToS       : {0}\n", tos);
            }
            buf += String.Format("   Total Len : {0}\n",  total_length);

            if (!brief)
            {
                buf += String.Format("   ID        : {0}\n", fragment_id);
                buf += String.Format("   Evil      : {0}\n", r);
                buf += String.Format("   Don't Frag: {0}\n", df);
                buf += String.Format("   More Frags: {0}\n", mf);
                buf += String.Format("   FragOffset: {0}\n", fragment_offset);
                buf += String.Format("   TTL       : {0}\n", ttl);
            }
            
            buf += String.Format("   Protocol  : {0}\n", protocol_s);

            if (!brief)
            {
                buf += String.Format("   Checksum  : {0}\n", header_checksum);
            }
            buf += String.Format("   src_ip    : {0}\n", source_ip_s);
            buf += String.Format("   dst_ip    : {0}\n", dest_ip_s);


            buf = buf.Replace("\n", Environment.NewLine);

            return buf;
        }
        
    }

    class myPCAPFile
    {
        public static System.IO.FileStream _file;

        public bool use_stdout { get; set; }

        void open(string _FileName)
        {
            if (use_stdout)
            {
                return;
            }

            try
            {
                _file = new System.IO.FileStream(_FileName, System.IO.FileMode.Create, System.IO.FileAccess.Write);
            }
            catch (Exception _Exception)
            {
                Console.WriteLine("Exception caught when creating logfile: {0}", _Exception.ToString());
                System.Environment.Exit(1);
            }
            return;
        }

        public void write(byte[] b, int length)
        {
            if (use_stdout)
            {
                using (System.IO.Stream stdout = Console.OpenStandardOutput())
                {
                    stdout.Write(b, 0, length);
                    stdout.Flush();
                }
                return;
            }
            _file.Write(b, 0, length);
        }

        public void close()
        {
            if (use_stdout)
            {
                return;
            }
            _file.Close();
            return;
        }

        public void start(string _FileName)
        {
            open(_FileName);
            //write(Convert.ToByte(0xA1B2C3D4), 1);

            //write(new byte[] { 0xA1, 0xB2, 0xB3, 0xB4 }, 4);

            uint magic = 2712847316;
            write(BitConverter.GetBytes(magic), 4);

            
            Int16 version_major = 2;
            Int16 version_minor = 4;
            uint thiszone = 0;
            uint sigfigs = 0;
            uint snaplen = 65535;
            uint network = 101;         // 101 is the code for "LINKTYPE_RAW" per http://www.tcpdump.org/linktypes.html

            write(BitConverter.GetBytes(version_major), 2);
            write(BitConverter.GetBytes(version_minor), 2);
            write(BitConverter.GetBytes(thiszone), 4);
            write(BitConverter.GetBytes(sigfigs), 4);
            write(BitConverter.GetBytes(snaplen), 4);
            write(BitConverter.GetBytes(network), 4);

        }

        public void writePacket(byte[] b, int length, uint ts_s, uint ts_us)
        {

            write(BitConverter.GetBytes(ts_s),4);
            write(BitConverter.GetBytes(ts_us),4);
            write(BitConverter.GetBytes(length), 4 );
            write(BitConverter.GetBytes(length), 4 );
            
            // ok now the data that we do have
            write(b, length);

            if (use_stdout)
            {
                return;
            }
            //_file.FlushAsync();//sometimes faster, builds with Visual Studio 2012, requires .NET Framework 4.5 
            _file.Flush();//could be slower, Builds e.g. with Visual Studio 2010, available since .NET Framework 1.1 
        }
    }


    class Program
    {
        public static string versionString = "rawsniff.exe 0.6 by Eli Fulkerson, Feb 24 2019";


        static int getPID(string x)
        {
            return 0;
        }

        public static string readable(byte[] b)
        {
            string s = System.Text.Encoding.Default.GetString(b);
            // no more wacky ascii
            s = Regex.Replace(s, @"[^\u0020-\u007F]", " ");

            // no more duplicate spaces
            s = Regex.Replace(s, @"[ ]{2,}", " ");
            s = s.TrimEnd(' ');

            return s;
        }

        static void showVersion()
        {

            Console.WriteLine(versionString);
            Console.WriteLine("See http://www.elifulkerson.com for updates.");
            //Console.ReadKey();
            Environment.Exit(0);

        }

        static void showHelp()
        {

            string helpstring = @"
Usage: rawsniff.exe [options]

Note:
    Must be administrator due to raw socket restrictions.  Also, antivirus may
    complain that you're opening a raw socket.  IPv4 only.

Options:
    -?            Get this help screen
    -v            Display version information
    --listen X    Listen on specified IP address (otherwise choose from list)

Types of packets:
    --tcp         Display TCP matches
    --udp         Display UDP matches
    --icmp        Display ICMP matches
    --other       Display matches for other protocols

Output options:
    --brief       Display brief (single line) packet information (default)
    --data        Brief mode, including readable ASCII data payloads
    --list        Display a list of packet information
    --full        Display the full list of packet information
    --gag         No output to console
    --pcap        Write out a timestamp.pcap file in the current directory.
                  (libpcap format)
    --packets X   Program exits after certain count of matching packets are
                  displayed (default is 2,147,483,647)

Filter:    
    --ip X        Match packets with this IP in either src_ip or dst_ip
    --port X      Match packets with this IP in either src_port or dst_port
    --src_ip X    If specified, display packets with a given src_ip only
    --dst_ip X    If specfied, display packets with a given dst_ip only
    --src_port X  If specified, display packets with a given src_port only
    --dst_port X  If specified, display packets with a given dst_port only

    --nopid       Disable the process info display, which is on by default.
    --pid X       If specified, display packets that belong to a given Process ID only
    --process X   If specified, display packets that belong to a given Process name only
";


            Console.WriteLine(helpstring);
            Environment.Exit(0);
        }

        public static string pickIP()
        {
            // Get host name
            String strHostName = Dns.GetHostName();

            // Find host by name
            IPHostEntry iphostentry = Dns.GetHostEntry(strHostName);

            int n = 0;
            Console.WriteLine("IP Address List:");
            Console.WriteLine("----------------");
            foreach (IPAddress ipaddress in iphostentry.AddressList)
            {
                Console.WriteLine("{0}: {1}", n, ipaddress.ToString());
                n += 1;
            }
            Console.WriteLine("");

            bool ok = false;
            while (!ok)
            {
                Console.Write("Please select an IPv4 address to listen on: ");
                //int which = Convert.ToInt32(Console.Read());
                int which;
                int.TryParse(Console.ReadLine(), out which);
                
                if (which >= 0 && which <= n)
                {
                    int n2 = 0;
                    foreach (IPAddress ipaddress in iphostentry.AddressList)
                    {
                        //Console.WriteLine("{0}: {1}", n, ipaddress.ToString());
                        if (n2 == which)
                        {
                            Console.WriteLine("{0} selected.", ipaddress.ToString());
                            Console.WriteLine();
                            return ipaddress.ToString();
                        }
                        n2 += 1;
                    }
                }
            }

            return "fail";
        }


        
        static void Main(string[] args)
        {

            //@@ first arg will be what IP to listen on

            //@@ need to parse flags here.
            // --brief, --tcp, --udp

            // --src_ip X, --dst_ip X, --src_port X, --dst_port X

            //@@ need to count the packets that match the pattern



            //@@ megabrief!
            //IP x.c.v.g:23->r.e.w.y:10844 size: SYN FIN HAT

            string listen_ip = "0.0.0.0";
            bool listen_udp = false;
            bool listen_tcp = false;
            bool listen_icmp = false;
            bool listen_other = false;
            int display_mode = 0;
            string src_ip_match = "";
            string dst_ip_match = "";
            int src_port_match = 0;
            int dst_port_match = 0;
            int any_port_match = 0;
            string any_ip_match = "";
            bool write_pcap = false;
            int max_numpackets = 0;


            bool match_pid = false;
            int pid = 0;

            bool match_process_name = false;
            string process_name = "";

            bool display_pinfo = true;

            bool write_raw_packets_to_stdout = false;
            //bool write_to_stdout = false;


            // First off, lets parse our arguments
            for (int x = 0; x < args.GetLength(0); x++)
            {
                // disabled the auto listen_ip stuff, pulling from a list is lazier
                //listen_ip = args[x];  // I'm lazy, this will eventually be the last argument on the line.

                //@@ someday write an args parser that I'm happy with.  No I don't want to pull in somebody elses complicated obnoxious .NET arg parser.
                if (args[x] == "-?" || args[x] == "/?" || args[x] == "?" || args[x] == "/help" || args[x] == "help" || args[x] == "--help")
                {
                    showHelp();
                    return;
                }

                if (args[x] == "-v" || args[x] == "/v" || args[x] == "/version" || args[x] == "--version" || args[x] == "-version")
                {
                    showVersion();
                    return;
                }

                if (args[x] == "--data" || args[x] == "/data" || args[x] == "-data")
                {
                    display_mode = 3;
                }

                if (args[x] == "--pcap" || args[x] == "/pcap" || args[x] == "-pcap")
                {
                    write_pcap = true;
                }

                if (args[x] == "--listen" || args[x] == "/listen" || args[x] == "-listen")
                {
                    listen_ip = args[x + 1];
                    x++;
                }

                if (args[x] == "--debug" || args[x] == "/debug" || args[x] == "-debug")
                {
                    // save for later
                }

                if (args[x] == "--tcp" || args[x] == "/tcp" || args[x] == "-tcp")
                {
                    listen_tcp = true;
                 
                }

                if (args[x] == "--udp" || args[x] == "/udp" || args[x] == "-udp")
                {
                    listen_udp = true;

                }

                if (args[x] == "--icmp" || args[x] == "/icmp" || args[x] == "-icmp")
                {
                    listen_icmp = true;

                }

                if (args[x] == "--other" || args[x] == "/other" || args[x] == "-other")
                {
                    listen_other = true;

                }

                if (args[x] == "--list" || args[x] == "/list" || args[x] == "-list")
                {
                    display_mode = 1;
                }

                if (args[x] == "--full" || args[x] == "/full" || args[x] == "-full")
                {
                    display_mode = 2;
                }

                if (args[x] == "--brief" || args[x] == "/brief" || args[x] == "-brief")
                {
                    display_mode = 0;
                }

                if (args[x] == "--gag" || args[x] == "/gag" || args[x] == "-gag")
                {
                    display_mode = -1;
                }

                if (args[x] == "--dump" || args[x] == "/dump" || args[x] == "-dump")
                {
                    // this is for instance:
                    // rawsniff.exe  --listen 192.168.2.20 --dump | "c:\Program Files\Wireshark\Wireshark.exe" -k -i -
                    write_raw_packets_to_stdout = true;
                    //write_to_stdout = true;
                    write_pcap = true;
                    // we want this to override the other display modes
                    display_mode = -1;  // --gag
                    
                }

                if (args[x] == "/src_ip" || args[x] == "--src_ip" || args[x] == "-src_ip")
                {
                    src_ip_match = args[x + 1];
                    x++;
                }

                if (args[x] == "/dst_ip" || args[x] == "--dst_ip" || args[x] == "-dst_ip")
                {
                    dst_ip_match = args[x + 1];
                    x++;
                }

                if (args[x] == "/nopid" || args[x] == "--nopid" || args[x] == "-nopid")
                {
                    display_pinfo = false;
                }

                if (args[x] == "/pid" || args[x] == "--pid" || args[x] == "-pid")
                {
                    display_pinfo = true;
                    match_pid = true;
                    pid = Convert.ToInt32(args[x + 1]);
                    x++;
                }

                if (args[x] == "/process" || args[x] == "--process" || args[x] == "-process")
                {
                    display_pinfo = true;
                    match_process_name = true;
                    process_name = args[x + 1];
                    x++;
                }

                if (args[x] == "/dst_port" || args[x] == "--dst_port" || args[x] == "-dst_port")
                {
                    try
                    {
                        dst_port_match = Convert.ToInt32(args[x + 1]);
                        if (dst_port_match < 1 || dst_port_match > 65535)
                        {
                            dst_port_match = 0;
                            Console.WriteLine("dst_port must be in range 1-65535");
                            return;
                        }
                    }
                    catch
                    {
                        Console.WriteLine("dst_port must be an integer");
                        return;
                    }
                    x++;
                }

                if (args[x] == "/src_port" || args[x] == "--src_port" || args[x] == "-src_port")
                {
                    try
                    {
                        src_port_match = Convert.ToInt32(args[x + 1]);
                        if (src_port_match < 1 || src_port_match > 65535)
                        {
                            src_port_match = 0;
                            Console.WriteLine("src_port must be in range 1-65535");
                            return;
                        }
                    }
                    catch
                    {
                        Console.WriteLine("src_port must be an integer");
                        return;
                    }
                    x++;
                }

                if (args[x] == "/ip" || args[x] == "--ip" || args[x] == "-ip")
                {
                    any_ip_match = args[x + 1];
                    x++;
                }

                if (args[x] == "/port" || args[x] == "--port" || args[x] == "-port")
                {
                    try
                    {
                        any_port_match = Convert.ToInt32(args[x + 1]);
                        if (any_port_match < 1 || any_port_match > 65535)
                        {
                            any_port_match = 0;
                            Console.WriteLine("port must be in range 1-65535");
                            return;
                        }
                    }
                    catch
                    {
                        Console.WriteLine("port must be an integer");
                        return;
                    }
                    x++;
                }

                if (args[x] == "/packets" || args[x] == "--packets" || args[x] == "-packets")
                {
                    try
                    {
                        max_numpackets = Convert.ToInt32(args[x + 1]);
                        if (max_numpackets < 1)
                        {
                            
                            Console.WriteLine("packets must be in range 1-{0}", int.MaxValue);
                            return;
                        }
                    }
                    catch
                    {
                        Console.WriteLine("packets must be in range 1-{0}", int.MaxValue);
                        return;
                    }
                    x++;
                }
            }
            
            // lets give the socket error message early if possible...
            try
            {
                using (Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP))
                {
                }
            }
            catch
            {
                Console.WriteLine("Error, cannot open RAW socket.  Are you Administrator?");
                Environment.Exit(1);
            }

            //if (args.GetLength(0) == 0)
            if (listen_ip == "0.0.0.0")
            {
                Console.WriteLine();
                Console.WriteLine("For help, use \"rawsniff.exe --help\"");
                //showHelp();
                Console.WriteLine();
                listen_ip = pickIP();
                //return;
            }

            if (!listen_tcp && !listen_udp && !listen_other && !listen_icmp)
            {
                // munging the defaults - if we haven't specified any, we are listening to all
                listen_udp = true;
                listen_tcp = true;
                listen_other = true;
                listen_icmp = true;
            }


            using (Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP))
            {
                try
                {
                    sock.Bind(new IPEndPoint(IPAddress.Parse(listen_ip), 0));
                    sock.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                    sock.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(1), null);
                }
                catch
                {
                    Console.WriteLine("Couldn't bind to specified IP, aborting...");
                    Environment.Exit(1);
                }
                int numpackets = 0;

                myPCAPFile log = new myPCAPFile();
                if (write_pcap)
                {
                    if (write_raw_packets_to_stdout)
                    {
                        log.use_stdout = true;
                        log.start("-");
                    }
                    else
                    {
                        log.use_stdout = false;
                        string filename = DateTime.UtcNow.ToString("yyyy-MM-dd-HH-mm-ss-ffffff") + ".pcap";
                        Console.WriteLine("Starting PCAP file: {0}", filename);
                        log.start(filename);
                    }
                }

                while (numpackets < int.MaxValue && (numpackets < max_numpackets || max_numpackets == 0))
                {
                    byte[] buffer = new byte[sock.ReceiveBufferSize];

                    int count = sock.Receive(buffer);
                    Int32 unixTimestamp = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
                    Int32 unixTimestampMS = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).Milliseconds * 1000;   // meh, close enough

                    



                    myIPPacket pkt = new myIPPacket();
                    myTCPSegment segTCP = new myTCPSegment();
                    myUDPSegment segUDP = new myUDPSegment();
                    myICMPSegment segICMP = new myICMPSegment();

                    pkt.slurp(buffer);

                    if (pkt.protocol_s == "TCP")
                    {
                        segTCP.slurp(buffer, pkt.header_len * 4);
                    }

                    if (pkt.protocol_s == "UDP")
                    {
                        segUDP.slurp(buffer, pkt.header_len * 4);
                    }

                    if (pkt.protocol_s == "ICMP")
                    {
                        segICMP.slurp(buffer, pkt.header_len * 4);
                    }

                    // Handle our display options, bail out
                    // Slightly less efficient than bailing out earlier if we weren't going to display the packet anyway, but kept all this
                    // together for conciseness.
                    if (listen_udp == false && pkt.protocol_s == "UDP") { continue; }
                    if (listen_tcp == false && pkt.protocol_s == "TCP") { continue; }
                    if (listen_icmp == false && pkt.protocol_s == "ICMP") { continue; }
                    if (listen_other == false && (pkt.protocol_s != "UDP" && pkt.protocol_s != "TCP" && pkt.protocol_s != "ICMP")) { continue; }

                    if (any_ip_match != "" && any_ip_match != pkt.source_ip_s && any_ip_match != pkt.dest_ip_s) { continue; }
                    if (any_port_match > 0 && any_port_match != segTCP.dst_port && any_port_match != segTCP.src_port && any_port_match != segUDP.src_port && any_port_match != segUDP.dst_port) { continue; }

                    if (dst_ip_match != "" && dst_ip_match != pkt.dest_ip_s) { continue; }
                    if (dst_port_match > 0 && dst_port_match != segTCP.dst_port && dst_port_match != segUDP.dst_port) { continue; }

                    if (src_ip_match != "" && src_ip_match != pkt.source_ip_s) { continue; }
                    if (src_port_match > 0 && src_port_match != segTCP.src_port && src_port_match != segUDP.src_port) { continue; }


                    if (match_pid == true)
                    {
                        if (pkt.protocol_s == "UDP" && ManagedIPHelperAPI.matchProcessUDP(pid, pkt.source_ip_s, segUDP.src_port, pkt.dest_ip_s, segUDP.dst_port) != true)
                        {
                            continue;
                        }

                        if (pkt.protocol_s == "TCP" && ManagedIPHelperAPI.matchProcessTCP(pid, pkt.source_ip_s, segTCP.src_port, pkt.dest_ip_s, segTCP.dst_port) != true)
                        {
                            continue;
                        }
                        // eh, I don't have a matchprocess for ICMP, so TCP/UDP only.
                        if (pkt.protocol_s != "TCP" && pkt.protocol_s != "UDP") {
                            continue;
                        }
                    }

                    if (match_process_name == true)
                    {
                        if (pkt.protocol_s == "UDP" && ManagedIPHelperAPI.matchProcessUDP(process_name, pkt.source_ip_s, segUDP.src_port, pkt.dest_ip_s, segUDP.dst_port) != true)
                        {
                            continue;
                        }


                        if (pkt.protocol_s == "TCP" && ManagedIPHelperAPI.matchProcessTCP(process_name, pkt.source_ip_s, segTCP.src_port, pkt.dest_ip_s, segTCP.dst_port) != true)
                        {
                            continue;
                        }
                        // eh, I don't have a matchprocess for ICMP, so TCP/UDP only.
                        if (pkt.protocol_s != "TCP" && pkt.protocol_s != "UDP") {
                            continue;
                        }
                    }

                    // @@tmp, get the process name for the display
                    string process_name_s = "";
                    int process_pid = 0;

                    if (display_pinfo == true)
                    {
                        if (pkt.protocol_s == "UDP")
                        {
                            process_name_s = ManagedIPHelperAPI.getProcessNameUDP(pkt.source_ip_s, segUDP.src_port, pkt.dest_ip_s, segUDP.dst_port);
                            process_pid = ManagedIPHelperAPI.getPIDUDP(pkt.source_ip_s, segUDP.src_port, pkt.dest_ip_s, segUDP.dst_port);
                        }
                        if (pkt.protocol_s == "TCP")
                        {
                            process_name_s = ManagedIPHelperAPI.getProcessNameTCP(pkt.source_ip_s, segTCP.src_port, pkt.dest_ip_s, segTCP.dst_port);
                            process_pid = ManagedIPHelperAPI.getPIDTCP(pkt.source_ip_s, segTCP.src_port, pkt.dest_ip_s, segTCP.dst_port);
                        }

                        // hack the pid in there
                        if (process_name_s.Length > 0 && process_pid != 0)
                        {
                            process_name_s = process_name_s + "," + process_pid.ToString();
                        }
                        else
                        {
                            process_name_s = "";
                        }
                    }


                    // at this point we must be past the matching logic
                    if (write_pcap)
                    {
                        log.writePacket(buffer, count, (uint)unixTimestamp, (uint)unixTimestampMS);
                    }
                    
                    numpackets++;

                    switch (display_mode)
                    {
                        case 0:
                            //--brief

                            switch (pkt.protocol_s)
                            {
                                case "TCP":
                                    //Console.WriteLine("{7} {0} {1}:{2} -> {3}:{4} size:{5} {6}", pkt.protocol_s, pkt.source_ip_s, segTCP.src_port, pkt.dest_ip_s, segTCP.dst_port, pkt.total_length, segTCP.flags_s(), numpackets);
                                    Console.WriteLine("{7} {0} {1}:{2} -> {3}:{4} size:{5} {6} {8}", pkt.protocol_s, pkt.source_ip_s, segTCP.src_port, pkt.dest_ip_s, segTCP.dst_port, pkt.total_length, segTCP.flags_s(), numpackets, process_name_s);
                                    break;
                                case "UDP":
                                    //Console.WriteLine("{6} {0} {1}:{2} -> {3}:{4} size:{5}", pkt.protocol_s, pkt.source_ip_s, segUDP.src_port, pkt.dest_ip_s, segUDP.dst_port, pkt.total_length, numpackets);
                                    Console.WriteLine("{6} {0} {1}:{2} -> {3}:{4} size:{5} {7}", pkt.protocol_s, pkt.source_ip_s, segUDP.src_port, pkt.dest_ip_s, segUDP.dst_port, pkt.total_length, numpackets, process_name_s);
                                    break;
                                case "ICMP":
                                    Console.WriteLine("{0} {1}  {2} -> {3} ({4},{5})", numpackets, pkt.protocol_s, pkt.source_ip_s, pkt.dest_ip_s, segICMP.type, segICMP.code);
                                    break;
                                default:
                                    Console.WriteLine("{4} {0} {1} -> {2} size:{3}", pkt.protocol_s, pkt.source_ip_s, pkt.dest_ip_s, pkt.total_length, numpackets);
                                    break;
                            }
                            break;

                        case 1:
                            // --list
                            switch (pkt.protocol_s)
                            {
                                case "TCP":
                                    Console.WriteLine("- PACKET {0}", numpackets);
                                    Console.WriteLine(pkt.display(true));
                                    Console.WriteLine(segTCP.display(true));
                                    break;
                                case "UDP":
                                    Console.WriteLine("- PACKET {0}", numpackets);
                                    Console.WriteLine(pkt.display(true));
                                    Console.WriteLine(segUDP.display(true));
                                    break;
                                case "ICMP":
                                    Console.WriteLine("- PACKET {0}", numpackets);
                                    Console.WriteLine(pkt.display(true));
                                    Console.WriteLine(segICMP.display(true));
                                    break;
                                default:
                                    Console.WriteLine("- PACKET {0}", numpackets);
                                    Console.WriteLine(pkt.display(true));
                                    break;
                            }

                            break;
                        case 2:
                            // --full
                            switch (pkt.protocol_s)
                            {
                                case "TCP":
                                    Console.WriteLine("- PACKET {0}", numpackets);
                                    Console.WriteLine(pkt.display(false));
                                    Console.WriteLine(segTCP.display(true));
                                    break;
                                case "UDP":
                                    Console.WriteLine("- PACKET {0}", numpackets);
                                    Console.WriteLine(pkt.display(false));
                                    Console.WriteLine(segUDP.display(true));
                                    break;
                                case "ICMP":
                                    Console.WriteLine("- PACKET {0}", numpackets);
                                    Console.WriteLine(pkt.display(false));
                                    Console.WriteLine(segICMP.display(true));
                                    break;
                                default:
                                    Console.WriteLine("- PACKET {0}", numpackets);
                                    Console.WriteLine(pkt.display(false));
                                    break;
                            }

                            break;

                        case 3:
                            // --data
                            switch (pkt.protocol_s)
                            {
                                case "TCP":
                                    var s_tcp = buffer.Take(segTCP.data_position);
                                    Console.WriteLine("{7} {0} {1}:{2} -> {3}:{4} size:{5} {6} data:{8}", pkt.protocol_s, pkt.source_ip_s, segTCP.src_port, pkt.dest_ip_s, segTCP.dst_port, pkt.total_length, segTCP.flags_s(), numpackets, readable(buffer));
                                    break;
                                case "UDP":
                                    var s_udp = buffer.Take(segUDP.data_position);
                                    Console.WriteLine("{6} {0} {1}:{2} -> {3}:{4} size:{5} data:{7}", pkt.protocol_s, pkt.source_ip_s, segUDP.src_port, pkt.dest_ip_s, segUDP.dst_port, pkt.total_length, numpackets, readable(buffer));
                                    break;
                                case "ICMP":
                                    var s_icmp = buffer.Take(segICMP.data_position);
                                    Console.WriteLine("{0} {1} {2} -> {3} ({4}:{6},{5}:{7}) {8}", numpackets, pkt.protocol_s, pkt.source_ip_s, pkt.dest_ip_s, segICMP.type, segICMP.code, segICMP.type_s, segICMP.code_s, readable(buffer));
                                    break;
                                default:
                                    var s_other = buffer.Take(pkt.data_position);
                                    Console.WriteLine("{4} {0} {1} -> {2} size:{3}", pkt.protocol_s, pkt.source_ip_s, pkt.dest_ip_s, pkt.total_length, numpackets, readable(buffer));
                                    break;
                            }

                            break;

                        case -1:
                            // no display
                            break;

                        default:
                            break;
                    }
                }
            }
        }
    }
}
