using System;
using System.Collections.Generic;
using System.Text;
using System.Net; // IPAddress
using System.Globalization; // NumberStyles
using System.Net.Sockets;
using System.Threading;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Base;
using System.Runtime.InteropServices;
using System.Net.NetworkInformation;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using System.Linq;


namespace tcproute {
	public static class DataHolder {
		// set the ttl here so that we can output the correct # when listenthread comes through
		// public static int ttl { get; set; }

		// set the desired destination here so listenthread can ignore other input
		public static string destination { get; set; }

		// are we done
		public static bool done { get; set; }

		// how many ms do we wait
		public static int opt_wait_time { get; set; }

		// how many times do we retry
		public static int opt_retry_times { get; set; }

		// are we doing http (default no)
		public static bool opt_do_http { get; set; }

		public static bool opt_debug_mode { get; set; }

		// Connection intitated, set state to 0 - when listenthread catches it, set state to 1
		// public static int state { get; set; }   // 0 for waiting for it, 1 for got it

		// This is a list of ICMP responders that we have already heard from, so we don't double up on their
		// responses (really, we only want the 1st response, but tcp will try three times)
		// public static string Responders { get; set; }

		// Stopwatch for timing.  Started by connectthread, stopped whenever we have a result
		public static System.Diagnostics.Stopwatch sw = new System.Diagnostics.Stopwatch();
		//public static long then { get; set; }

		public static HiResTimer hrt = new HiResTimer();
		public static Int64 hrt_start;
		public static Int64 hrt_stop;

		public static bool dns_lookup;

		public static bool redact_output { get; set; }


		public static string FormatIP(string ip) {
			//int num_backspaces = ip.Length();

			if (DataHolder.dns_lookup == true) {
				try {
					IPAddress addr = IPAddress.Parse(ip);
					return Dns.GetHostEntry(addr).HostName + " [" + ip + "]";
				}
				catch {
					return ip;
				}
			}
			else {
				return ip;
			}
		}


		public static void PrintIP(string ip) {
			//int num_backspaces = ip.Length;
			string dnsmsg = " ";

			if (DataHolder.redact_output == true) {
				Console.Write("(redacted)");
				return;
			}

			string backoff = String.Concat(Enumerable.Repeat("\b", ip.Length + dnsmsg.Length));
			//string backoff = String.Concat(Enumerable.Repeat("\b", 5));

			if (DataHolder.dns_lookup == true) {
				Console.Write(ip + dnsmsg);
				try {
					IPAddress addr = IPAddress.Parse(ip);
					string hostname = Dns.GetHostEntry(addr).HostName;
					//Console.Write(backoff);

					for (int a = 0; a < backoff.Length; a++) {
						Console.Write("\b \b");
						Console.Out.Flush();

						Thread.Sleep(10);
					}
					Console.Write(hostname + " [" + ip + "]");
				}
				catch {
					//Console.Write(backoff);
					for (int a = 0; a < dnsmsg.Length; a++) {
						Console.Write("\b \b");
						Console.Out.Flush();
						Thread.Sleep(10);
					}
					//Console.Write(ip);
				}
			}
			else {
				Console.Write(ip);
			}
		}
	}

	internal class Program {
		[DllImport("iphlpapi.dll", ExactSpelling = true)]
		public static extern int SendARP(uint destIP, uint srcIP, byte[] macAddress, ref uint macAddressLength);

		public static string versionString = "tcproute.exe 0.9 by Eli Fulkerson, Sep 2 2015\n";

		public static void DebugPrint(string msg) {
			if (DataHolder.opt_debug_mode == true) {
				Console.ForegroundColor = ConsoleColor.Green;
				Console.WriteLine(msg);
				Console.ResetColor();
			}
		}

		private static void showVersion() {
			Console.WriteLine(versionString);
            Console.WriteLine("See http://www.elifulkerson.com/projects/tcproute.php for updates.");
			Environment.Exit(0);
		}

		private static void showHelp() {
			string helpstring = @"
Usage: tcproute.exe [-?][-l][-i INTERFACE#][-p PORT] target

Options:
    -?          Get this help screen
    -v          Display version information
    -l          List available interfaces
    -i INT#     Specify an interface (otherwise you have to pick from the list)
    -p PORT     Specify a TCP port to connect to
    -d          Disable DNS lookup
    -h num      Maximum of 'num' hops (maximum TTL)
    -w ms       Wait 'ms' milliseconds for a response
    -r #        Retry # times if a hop times out
    --http      Send an HTTP request once we get a connection
    target      The IP address or domain name of the target
    --debug     Debug mode, prints stuff for bug reports
    -x          redact ip/domain output


Manual (Override) Options:
    --local-ip or --lip
        Manually set the local IP address.  
        (format) XXX.XXX.XXX.XXX
    
    --local-mac or --lmac
        Manually set the local MAC address.
        (format)  XX:XX:XX:XX:XX:XX:XX  (colons only)

    --gateway-mac or --gwmac
        Manually set the gateway's MAC address
        (format)  XX:XX:XX:XX:XX:XX:XX  (colons only)
 
";


			Console.WriteLine(helpstring);
			showVersion();
			Environment.Exit(0);
		}

		private static void listDevices(IList<LivePacketDevice> devices) {
			for (int x = 0; x != devices.Count; x++) {
				LivePacketDevice device = devices[x];
				Console.Write((x + 1) + ". ");
				if (device.Description != null)
					Console.Write(" " + device.Description);
				else
					Console.Write(" No description available");

				Console.WriteLine();
				Console.WriteLine("     " + device.Name);

				foreach (PcapDotNet.Core.DeviceAddress addy in device.Addresses) {
					//if (addy.Address.Family.ToString() == "Internet")
					//{
					Console.WriteLine("     " + addy.Address);
					//}
					//Console.WriteLine(addy.Address.Family.ToString());
				}
				Console.WriteLine();
			}
		}

		private static void Main(string[] args) {
			NetworkInterface[] netInterfaces = NetworkInterface.GetAllNetworkInterfaces();
			/*Console.ReadLine();
			foreach (var networkInterface in netInterfaces) {
				var ipProps = networkInterface.GetIPProperties();
				IPv4InterfaceProperties p = ipProps.GetIPv4Properties();
				Console.WriteLine(networkInterface.Name + " - gw=" + networkInterface.GetIPProperties().GatewayAddresses + ", " + networkInterface.GetIPProperties().GetIPv4Properties()+" ip: "+string.Join(", ", ipProps.UnicastAddresses.Where(w => w.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).Select(s => s.Address.ToString())));
			}
			 */

			//DataHolder.Responders = "";

			// if we don't have pcap, lets just go home.
			IList<LivePacketDevice> devices = LivePacketDevice.AllLocalMachine;

			int opt_abort = -1; // This is slightly messy, but we still want to be able to get into the command parser to show the /help even w/out pcap.
			if (devices.Count == 0) {
				Console.WriteLine("WinPcap is not installed.");
				opt_abort = 1;
				//return;
			}

			int opt_interface = -1;
			string opt_target = "127.0.0.1";
			int opt_max_hops = 32;
			int opt_port = 80;
			bool opt_dns_lookup = true;

			string opt_local_ip = "";
			string opt_local_mac = "";
			string opt_gateway_mac = "";
			string opt_gateway_ip = "";


			DataHolder.opt_do_http = false;
			DataHolder.opt_wait_time = 2000;
			DataHolder.opt_retry_times = 3;
			DataHolder.opt_debug_mode = false;

			IPAddress local_ip;
			IPAddress gateway_ip;


			// First off, lets parse our arguments
			for (int x = 0; x < args.GetLength(0); x++) {
				opt_target = args[x]; // I'm lazy, this will eventually be the last argument on the line.

				if (args[x] == "-?" || args[x] == "/?" || args[x] == "?" || args[x] == "/help" || args[x] == "help" || args[x] == "--help") {
					showHelp();
					return;
				}

				if (args[x] == "-v" || args[x] == "/v" || args[x] == "/version" || args[x] == "--version") {
					showVersion();
					return;
				}

				if (opt_abort == 1) {
					return;
				}

				if (args[x] == "--debug" || args[x] == "/debug") {
					DataHolder.opt_debug_mode = true;
				}

				if (args[x] == "-d") {
					opt_dns_lookup = false;
				}

				if (args[x] == "/http" || args[x] == "--http") {
					DataHolder.opt_do_http = true;
				}

				if (args[x] == "-w" || args[x] == "--wait" || args[x] == "/w" || args[x] == "/wait") {
					try {
						DataHolder.opt_wait_time = Convert.ToInt32(args[x + 1]);
						x++;
						continue;
					}
					catch {
						Console.WriteLine("Wait time must be an integer.");
						return;
					}
				}

				if (args[x] == "-r" || args[x] == "--retry" || args[x] == "/r" || args[x] == "/retry") {
					try {
						DataHolder.opt_retry_times = Convert.ToInt32(args[x + 1]);
						x++;
						continue;
					}
					catch {
						Console.WriteLine("Number of retry times must be an integer.");
						return;
					}
				}


				if (args[x] == "-p" || args[x] == "--port") {
					try {
						opt_port = Convert.ToInt32(args[x + 1]);
						if (opt_port < 1 || opt_port > 65535) {
							Console.WriteLine("Port must be between 1 and 65535");
							Environment.Exit(0);
							//opt_port = 80;
						}
						x++;
						continue;
					}
					catch {
					}
				}

				if (args[x] == "-i" || args[x] == "--interface") {
					try {
						opt_interface = Convert.ToInt32(args[x + 1]);
						if (opt_interface > devices.Count || opt_interface < 1) {
							// they failed at picking a device
							//Console.WriteLine("device picking failure, reverting to -1");
							opt_interface = -1;
						}

						//Console.WriteLine("using interface " + opt_interface);
						x++;
						continue;
					}
					catch {
					}
				}

				if (args[x] == "-l" || args[x] == "--list") {
					Console.WriteLine("Available interfaces:  (use with -i to select)");
					listDevices(devices);
					return;
				}

				if (args[x] == "-x") {
					Console.WriteLine("Redact-o-matic enabled!");
					DataHolder.redact_output = true;
				}


				if (args[x] == "-h" || args[x] == "--hops") {
					try {
						opt_max_hops = Convert.ToInt32(args[x + 1]);
					}
					catch {
						opt_max_hops = 0;
					}

					if (opt_max_hops < 1) {
						Console.WriteLine("Maximum hops must be an integer > 0");
						return;
					}
					x++;
				}

				if (args[x] == "--local-ip" || args[x] == "--lip") {
					try {
						opt_local_ip = args[x + 1];
						local_ip = IPAddress.Parse(opt_local_ip);
					}
					catch {
						Console.WriteLine("Error trying to convert " + opt_local_ip + " to an IP Address.");
						return;
					}
					x++;
				}

				if (args[x] == "--local-mac" || args[x] == "--lmac") {
					opt_local_mac = args[x + 1];
					x++;
				}

				if (args[x] == "--gateway-mac" || args[x] == "--gwmac") {
					opt_gateway_mac = args[x + 1];
					x++;
				}
			}


			Program.DebugPrint(@"Hi!

Since you care enough to run the --debug option, here is my email address:

elifulkerson@gmail.com

Please send your bug reports there, with as much description of what you did, what
happened, what you expected to happen, etc.  Also include any pertinent platform information
(OS version, WinPCap version, etc)

Non bug related feedback, suggestions, etc are welcome too.
            
            ");


			Program.DebugPrint("args: " + args.SequenceToString(" "));
			Program.DebugPrint("version: " + versionString);

			DataHolder.dns_lookup = opt_dns_lookup;

			if (opt_interface == -1) {
				Console.WriteLine("Available interfaces:  (use with -i to avoid interaction next time)");
				listDevices(devices);

				int deviceIndex = 0;
				do {
					Console.WriteLine("Select the listening interface (1-" + devices.Count + "):");
					string deviceIndexString = Console.ReadLine();
					if (!int.TryParse(deviceIndexString, out deviceIndex) ||
					    deviceIndex < 1 || deviceIndex > devices.Count) {
						deviceIndex = 0;
					}
				} while (deviceIndex == 0);

				opt_interface = deviceIndex;
			}

			// Use the selected adapter
			PacketDevice selectedDevice = devices[opt_interface - 1];

			// ok, lets figure out all the other stuff we need for packet creation
			if (opt_local_ip == "") {
				Program.DebugPrint("Entering magic opt_local_ip zone...");
				//Console.WriteLine("Pineapple Z ");
				//Console.WriteLine(selectedDevice.Addresses.Count);
				foreach (object x in selectedDevice.Addresses) {
					//int tmp_cnt = selectedDevice.Addresses.Count + 0;
					//for (int i = 0; i < tmp_cnt; i++)
					//{
					//object x = selectedDevice.Addresses[i];
					//Console.WriteLine("Pineapple Y ");
					//Console.WriteLine(x.ToString());

					string[] sd = x.ToString().Split(' ');

					if (sd[1] == "Internet") {
						//Console.WriteLine("Pineapple X ");
						opt_local_ip = sd[2];
						break;
					}
					//}
				}
			}

			if (string.IsNullOrEmpty(opt_local_ip)) {
				//find intrface IP addresses
				List<IPAddress> ipAdresses = netInterfaces.Where(w => selectedDevice.Name.Contains(w.Id)).Select(s => s.GetIPProperties()).SelectMany(s => s.UnicastAddresses).Where(w => w.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).Select(s => s.Address).ToList();
				if (ipAdresses.Count == 0) {
					Console.WriteLine("Can't find IP address for interface: " + selectedDevice.Name);
					return;
				}
				else {
					Console.WriteLine("All found addresses: " + string.Join(", ", ipAdresses));
					local_ip = ipAdresses.First();
					opt_local_ip = local_ip.ToString();
				}
			}
			else {
				local_ip = IPAddress.Parse(opt_local_ip);
			}

			if (opt_local_mac == "") {
				Program.DebugPrint("Entering magic opt_local_mac zone");
				// redundant, but C# is complaining otherwise
				try {
					opt_local_mac = GetMacAddress(local_ip);
				}
				catch (Exception ex) {
					Console.WriteLine("Failed to find MAC for " + local_ip + ",  Ex=" + ex.Message);
					Console.WriteLine("Can't use traceroute on interface " + selectedDevice.Name + " Aborting.");
					return;
				}
				//opt_local_mac = IPInfo.GetMACInfo(opt_local_ip).MacAddress;
				//opt_local_mac = GetMacAddress2(opt_local_ip);
			}

			if (opt_gateway_mac == "") {
				Program.DebugPrint("Entering magic opt_gateway_mac zone");
				//Console.WriteLine("Pineapple 1 ");
				// dig up the gateway
				foreach (NetworkInterface f in netInterfaces) {
					//Console.WriteLine("Pineapple 2 ");
					if (f.OperationalStatus == OperationalStatus.Up && selectedDevice.Name.Contains(f.Id) /*work with correct interface*/&& opt_gateway_mac == "") {
						//Console.WriteLine("Pineapple 3 ");
						bool gwFound = false;
						foreach (GatewayIPAddressInformation gw in f.GetIPProperties().GatewayAddresses) {
							//Console.WriteLine(d.Address.AddressFamily);

							if (gw.Address.AddressFamily.ToString() == "InterNetwork") {
								//Console.WriteLine(d.Address.ToString());
								gateway_ip = IPAddress.Parse(gw.Address.ToString());

								// OK - lets get the gateway into ARP real fast, just in case...
								if (DataHolder.redact_output == false) {
									Console.Write("Ensuring gateway address (" + gw.Address.ToString() + ") is in arp...");
								}
								else {
									Console.Write("Ensuring gateway address (redacted) is in arp...");
								}
								if (gw.Address.ToString() == "0.0.0.0") {
									Console.WriteLine("Gw address is " + gw.Address + ", not pinging");
								}
								else {
									Ping pingSender = new Ping();
									PingReply reply = pingSender.Send(gw.Address);
									if (reply.Status == IPStatus.Success) {
										Console.WriteLine(" OK!");
										//Console.WriteLine("Address: {0}", reply.Address.ToString());
										//Console.WriteLine("RoundTrip time: {0}", reply.RoundtripTime);
										//Console.WriteLine("Time to live: {0}", reply.Options.Ttl);
										//Console.WriteLine("Don't fragment: {0}", reply.Options.DontFragment);
										//Console.WriteLine("Buffer size: {0}", reply.Buffer.Length);
									}
									else {
										Console.WriteLine("Ping failed, aborting");
										return;
									}
								}

								try {
									opt_gateway_mac = GetMacAddress(gateway_ip);
								}
								catch (Exception ex) {
									Console.WriteLine("Error getring ARP for " + gateway_ip + ": " + ex.Message);
									opt_gateway_mac = string.Join(":", f.GetPhysicalAddress().GetAddressBytes().Select(s => s.ToString("X2")));
									//Console.WriteLine("Mac for: " + GetMacAddress(IPAddress.Parse("10.200.200.200")));
									Console.WriteLine("Set GW mac same as interface mac: " + opt_gateway_mac);
								}
								gwFound = true;
								//opt_gateway_mac = IPInfo.GetMACInfo(d.Address.ToString()).MacAddress;
								break;
							}
						}
						if (!gwFound) {
							Console.WriteLine("No GW addresses found for interface:\r\n Name=" + f.Name + "\r\n Id=" + f.Id + "\r\n Desc=" + f.Description + "\r\n Ip=" + local_ip + "\r\nAborting!");
							return;
						}
					}
				}
			}
			Console.WriteLine("");
			Console.WriteLine("Using the following values:");
			Console.WriteLine("---------------------------");
			if (DataHolder.redact_output == false) {
				Console.WriteLine("Local IP:    " + opt_local_ip);
				Console.WriteLine("Local MAC:   " + opt_local_mac);
				Console.WriteLine("Gateway MAC: " + opt_gateway_mac);
			}
			else {
				Console.WriteLine("Local IP:    " + "(redacted)");
				Console.WriteLine("Local MAC:   " + "(redacted)");
				Console.WriteLine("Gateway MAC: " + "(redacted)");
			}


			int ttl = 1;
			DataHolder.done = false;


			IPHostEntry ipHostInfo;
			IPAddress ipAddress;
			try {
				ipHostInfo = Dns.GetHostEntry(opt_target);

				ipAddress = ipHostInfo.AddressList[0]; //  leaving this line because C# bitches otherwise, but it is overriden below

				foreach (IPAddress ip in ipHostInfo.AddressList) {
					// rule out the ipv6s
					if (ip.AddressFamily.ToString() == "InterNetwork") {
						ipAddress = ip;
						break;
					}
				}
			}
			catch (Exception e) {
				//Console.WriteLine(e.Message);
				//Console.WriteLine("banana");
				try {
					ipAddress = Dns.GetHostAddresses(opt_target)[0];
				}
				catch {
					Console.WriteLine("");
					Console.WriteLine("Error with specified hostname: " + opt_target + ", aborting...");
					return;
				}
			}


			if (DataHolder.redact_output == false) {
				Console.WriteLine("Remote IP:   " + ipAddress.ToString());
				Console.WriteLine("");
				Console.WriteLine("Tracing route to " + opt_target + ":" + opt_port);
			}
			else {
				Console.WriteLine("Remote IP:   " + "(redacted)");
				Console.WriteLine("");
				Console.WriteLine("Tracing route to " + "(redacted)");
			}


			DataHolder.destination = ipAddress.ToString();
			//Console.WriteLine(DataHolder.destination);

			while (DataHolder.done == false && ttl <= opt_max_hops) {
				//Console.WriteLine("STARTING ANEW AT " + ttl);
				HttpGetSender sender = new HttpGetSender
					                       {
						                       SourceMac = new MacAddress(opt_local_mac),
						                       DestinationMac = new MacAddress(opt_gateway_mac),
						                       SourceIpV4 = new IpV4Address(opt_local_ip),
						                       DestinationIpV4 = new IpV4Address(DataHolder.destination),
						                       _TTL = ttl,
						                       _PORT = (ushort) opt_port,
						                       Host = opt_target,
					                       };

				DataHolder.sw.Restart();
				DataHolder.hrt_start = DataHolder.hrt.Value;

				//DataHolder.then = DataHolder.sw.ElapsedMilliseconds;
				sender.Run(selectedDevice);

				ttl += 1;
				//Thread.Sleep(1000);
			}
		}

		//@@FROM http://stackoverflow.com/questions/2135678/get-mac-address-from-default-gateway
		// Creative commons?
		public static string GetMacAddress(IPAddress address) {
			byte[] mac = new byte[6];
			uint len = (uint) mac.Length;
			byte[] addressBytes = address.GetAddressBytes();
			uint dest = ((uint) addressBytes[3] << 24)
			            + ((uint) addressBytes[2] << 16)
			            + ((uint) addressBytes[1] << 8)
			            + ((uint) addressBytes[0]);
			if (SendARP(dest, 0, mac, ref len) != 0) {
				Console.WriteLine(mac[2].ToString("X2"));
				throw new Exception("The ARP request failed.");
			}
			//return mac;

			string m = "";
			for (int i = 0; i <= 5; i++) {
				m = m + mac[i].ToString("X2") + ":";
			}

			m = m.TrimEnd(':');
			return m;
		}

		/*
        //@@FROM http://stackoverflow.com/questions/12802888/get-a-machines-mac-address-on-the-local-network-from-its-ip-in-c-sharp
        public static string GetMacAddress2(string ipAddress)
        {
            string macAddress = string.Empty;
            System.Diagnostics.Process pProcess = new System.Diagnostics.Process();
            pProcess.StartInfo.FileName = "arp";
            pProcess.StartInfo.Arguments = "-a " + ipAddress;
            pProcess.StartInfo.UseShellExecute = false;
            pProcess.StartInfo.RedirectStandardOutput = true;
            pProcess.StartInfo.CreateNoWindow = true;
            pProcess.Start();
            string strOutput = pProcess.StandardOutput.ReadToEnd();
            string[] substrings = strOutput.Split('-');
            if (substrings.Length >= 8)
            {
                macAddress = substrings[3].Substring(Math.Max(0, substrings[3].Length - 2))
                         + "-" + substrings[4] + "-" + substrings[5] + "-" + substrings[6]
                         + "-" + substrings[7] + "-"
                         + substrings[8].Substring(0, 2);
                return macAddress;
            }

            else
            {
                return "not found";
            }
        }
         */
	}
}