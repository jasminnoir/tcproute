//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Text;

using System;
using System.Collections.Generic;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System.Net.NetworkInformation;
using System.Net;
using System.Globalization;

using System.Threading;


// @@From http://stackoverflow.com/questions/21102104/creating-a-valid-tcp-connection-in-pcap-net
// ... heavily mangled at this point - Eli

namespace tcproute
{
    class HttpGetSender
    {
        public HttpGetSender()
        {
        }

        public MacAddress SourceMac { get; set; }
        public MacAddress DestinationMac { get; set; }
        public IpV4Address SourceIpV4 { get; set; }
        public IpV4Address DestinationIpV4 { get; set; }
        public string Host { get; set; }

        public int _TTL { get; set; }
        public ushort _PORT { get; set; }

        public void Run(PacketDevice device)
        {
            using (PacketCommunicator communicator = device.Open(100, // name of the device
                                                                 PacketDeviceOpenAttributes.Promiscuous,
                // promiscuous mode
                                                                 1)) // read timeout
            {
                //SendSyn(communicator);
                WaitForAck(communicator);
            }
        }

        
public string IPtoHexStr(string ipaddr)
{
	int i;
	string[] octets;
	string buff = "";

	octets = ipaddr.Split('.');
	for (i = 0; i < 4; i++) {
	   //buf += octets[i].ToString("X2");
       //buf += octets[i].ToString();
       buff += Convert.ToInt16(octets[i]).ToString("x2");
	}

    return buff;

}



        private void WaitForAck(PacketCommunicator communicator)
        {
            Int64 hrt_took;
            int num_attempts = 1;
            // using a stopwatch to control re-sending
            System.Diagnostics.Stopwatch resendTimer = new System.Diagnostics.Stopwatch();
            
            //communicator.SetFilter("tcp and src " + DestinationIpV4 + " and dst " + SourceIpV4 + " and src port " + _destinationPort + " and dst port " + _sourcePort);
            communicator.SetFilter("(tcp and src " + DestinationIpV4 + " and dst " + SourceIpV4 + " and src port " + _PORT + " and dst port " + _sourcePort + ") or (icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply)");
            Packet packet;
            resendTimer.Start();
            SendSyn(communicator);
            while (true)
            {
                if (communicator.ReceivePacket(out packet) == PacketCommunicatorReceiveResult.Ok)
                {
                    long now = DataHolder.sw.ElapsedMilliseconds;
                    DataHolder.hrt_stop = DataHolder.hrt.Value;

                    hrt_took = ((DataHolder.hrt_stop - DataHolder.hrt_start) * 1000) / DataHolder.hrt.Frequency;

                    //DataHolder.then = DataHolder.sw.ElapsedMilliseconds;
                    Program.DebugPrint("Potential Packet received from communicator...");
                    //Console.WriteLine(packet.IpV4.Source.ToString());

                   //try
                   //
                    //Console.WriteLine(packet.Ethernet.IpV4.Tcp.ControlBits.ToString());
                    //@@ really just need to be able to identity the packet type here thenI think we are GTG bears. @@@@@@@@
                    //try
                    //{
                    Program.DebugPrint("Messagetype is... " + packet.Ethernet.IpV4.Icmp.MessageType.ToString());
                    if (packet.Ethernet.IpV4.Icmp.MessageType.ToString() == "TimeExceeded" )
                        //|| packet.Ethernet.IpV4.Icmp.MessageType.ToString() == "DestinationUnreachable")
                        
                        {
                            //Program.DebugPrint("number is:" + DataHolder.destination.ToString() );
                            //Program.DebugPrint(IPtoHexStr(DataHolder.destination.ToString() ));

                            //Console.WriteLine("TIMESTAMP!!! : " + (packet.Timestamp.Millisecond - DataHolder.then));
                            //Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff"));


                            Program.DebugPrint("...its a time-exceeded");
                            string hex = packet.IpV4.Icmp.Payload.ToHexadecimalString();
                            
                            Program.DebugPrint("...its got a payload");

                            Program.DebugPrint("* The length of our Icmp Payload hex is: " + hex.Length.ToString());
                            Program.DebugPrint("The index for our ip_dst is:" + hex.IndexOf(IPtoHexStr(DataHolder.destination.ToString())));

                            //string hex = packet.IpV4.Icmp.Payload.ToHexadecimalString();
                            //string ip_src = "";
                            string ip_dst = "";
                            
                            //if (hex.Length >= 116)
                            //{
                            /*
                                Program.DebugPrint("* calculating ip_src");
                                int offset = 92;
                                ip_src = hex.Substring(offset, 8);
                                ip_src = hex.Substring(offset + 6, 2) + hex.Substring(offset + 4, 2) + hex.Substring(offset + 2, 2) + hex.Substring(offset + 0, 2);  // eww, byte order
                                Program.DebugPrint("ip_src: " + ip_src);

                                Program.DebugPrint("* calculating ip_dst");
                                ip_dst = hex.Substring(offset + 8, 8);
                                ip_dst = hex.Substring(offset + 14, 2) + hex.Substring(offset + 12, 2) + hex.Substring(offset + 10, 2) + hex.Substring(offset + 8, 2);  // eww, byte order
                                Program.DebugPrint("ip_dst: " + ip_dst);
                             */
                            //}
                            //else
                            //{
                                //Program.DebugPrint("short payload");
                                if (hex.IndexOf(IPtoHexStr(DataHolder.destination.ToString())) == -1)
                                {
                                    Program.DebugPrint("*** Uh, oh - we didn't even find the ip_dst in the payload, strange");
                                }
                                else
                                {
                                    int new_offset = hex.IndexOf(IPtoHexStr(DataHolder.destination.ToString()));
                                    Program.DebugPrint("ip_dst we were looking for was found in location " + new_offset + " so we're calling it good...");
                                    // ugly cut/paste but I don't want to deal with reversing the byte order right here so I'm reading it back out of the packet from where we found it, ugh
                                    ip_dst = hex.Substring(new_offset + 6, 2) + hex.Substring(new_offset + 4, 2) + hex.Substring(new_offset + 2, 2) + hex.Substring(new_offset + 0, 2);  // eww, byte order
                                }
                            //}

                            /*
                            Program.DebugPrint("* calculating ip_src_port");
                            //Console.WriteLine("ICMP BABY!  2");
                            string ip_src_port = hex.Substring(offset + 16, 4);
                            Program.DebugPrint("ip_src_port: " + ip_src_port);

                            Program.DebugPrint("* calculating ip_dst_port");
                            //string ip_src_port = hex.Substring(offset + 19, 1) + hex.Substring(offset + 18, 1) + hex.Substring(offset + 17, 1) + hex.Substring(offset + 16, 1);
                            string ip_dst_port = hex.Substring(offset + 20, 4);
                            Program.DebugPrint("ip_dst_port: " + ip_dst_port);
                            */

                            //Console.WriteLine(packet.IpV4.Icmp.Code.ToString() + " " + packet.IpV4.Source.ToString() + " says timeout.   ip_src=" + ip_src + ":" + ip_src_port + "  ip_dst=" + ip_dst + ":" + ip_dst_port);

                            PcapDotNet.Packets.IpV4.IpV4Datagram ip = packet.Ethernet.IpV4;
                            //PcapDotNet.Packets.Transport.UdpDatagram udp = ip.Udp;

                            //var ip_src_addr = new IPAddress(long.Parse(ip_src, NumberStyles.AllowHexSpecifier));
                            Program.DebugPrint("Parsing " + ip_dst + "as an IP....");

                            IPAddress ip_dst_addr;
                            try
                            {
                                ip_dst_addr = new IPAddress(long.Parse(ip_dst, NumberStyles.AllowHexSpecifier));
                                Program.DebugPrint("Parse result: " + ip_dst_addr.ToString());
                            }
                            catch
                            {
                                Program.DebugPrint("Parsing " + ip_dst + "as an IP.... failed");
                                // using a deliberately bad class E address here so we won't match
                                ip_dst_addr = new IPAddress(long.Parse("feffffff", NumberStyles.AllowHexSpecifier));

                                /*
                                // ok we didn't get a matching dest, so report it anyway @@dupe code with matching destinations below
                                //Program.DebugPrint("It matched our ip_dst_addr!");
                                DataHolder.sw.Stop();
                                //long milliseconds = DataHolder.sw.ElapsedTicks / (System.Diagnostics.Stopwatch.Frequency / (1000L));
                                //long milliseconds = DataHolder.sw.ElapsedMilliseconds;
                                long milliseconds = now;
                                //Console.Write(String.Format("{0,3}", DataHolder.ttl) + "\t" + String.Format("{0,5} ms", milliseconds) + "\t");
                                //Console.Write(String.Format("{0,3}", _TTL) + "\t" + String.Format("{0,5} ms", milliseconds) + "\t");
                                Console.Write(String.Format("{0,3}", _TTL) + "\t" + String.Format("{0,5} ms", hrt_took) + "\t");

                                //Console.Write(DataHolder.FormatIP(ip.Source.ToString()));
                                DataHolder.PrintIP(ip.Source.ToString());
                                //DataHolder.PrintIP(ip_src_addr.ToString());
                                Console.WriteLine("\t" + packet.Ethernet.IpV4.Icmp.MessageType.ToString());
                                Console.WriteLine("\t (but no match)");

                                return;
                                */

                            }



                            //if (DataHolder.Responders.Contains(ip.Source.ToString()))
                            //{
                            //Console.WriteLine("duplicate:" + DataHolder.Responders.ToString() + "," + ip.Source.ToString() );
                            //}
                            //else
                            //{
                            // make sure the ICMP in question is actually referring to our desired destination...
                            Program.DebugPrint("* matching destinations");
                            if (DataHolder.destination == ip_dst_addr.ToString())
                            {
                                Program.DebugPrint("It matched our ip_dst_addr!");
                                DataHolder.sw.Stop();
                                //long milliseconds = DataHolder.sw.ElapsedTicks / (System.Diagnostics.Stopwatch.Frequency / (1000L));
                                //long milliseconds = DataHolder.sw.ElapsedMilliseconds;
                                long milliseconds = now;
                                //Console.Write(String.Format("{0,3}", DataHolder.ttl) + "\t" + String.Format("{0,5} ms", milliseconds) + "\t");
                                //Console.Write(String.Format("{0,3}", _TTL) + "\t" + String.Format("{0,5} ms", milliseconds) + "\t");
                                Console.Write(String.Format("{0,3}", _TTL) + "\t" + String.Format("{0,5} ms", hrt_took) + "\t");

                                //Console.Write(DataHolder.FormatIP(ip.Source.ToString()));
                                DataHolder.PrintIP(ip.Source.ToString());
                                //DataHolder.PrintIP(ip_src_addr.ToString());
                                Console.WriteLine("\t" + packet.Ethernet.IpV4.Icmp.MessageType.ToString());

                                return;
                            }
                            else
                            {
                                Program.DebugPrint("Packet didn't refer to destination, actually...");
                            }

                            //DataHolder.Responders = DataHolder.Responders + " " + ip.Source.ToString();
                            //DataHolder.state = 1;
                            // return;
                            //} 
                            //}
                            //catch
                            //{
                            //Console.WriteLine("NOT ICMP BABY :(");
                            //}
                        }
                    //}
                    //catch { }
                    Program.DebugPrint("* fell out of old problematic try/catch area");

                    if (packet.Ethernet.IpV4.Tcp.AcknowledgmentNumber == _expectedAckNumber)
                    {
                        Program.DebugPrint("... packet is TCP with a matching ACK number");
                        _seqNumber = _expectedAckNumber;
                        
                        _ackNumber = packet.Ethernet.IpV4.Tcp.SequenceNumber + 1;

                        
                        //@@ need to differentiate open port vs closed port here
                        
                        DataHolder.sw.Stop();
                        DataHolder.hrt_stop = DataHolder.hrt.Value;

                        hrt_took = ((DataHolder.hrt_stop - DataHolder.hrt_start) * 1000) / DataHolder.hrt.Frequency;
                        //long milliseconds = DataHolder.sw.ElapsedTicks / (System.Diagnostics.Stopwatch.Frequency / (1000L));
                        //long milliseconds = DataHolder.sw.ElapsedMilliseconds;
                        long milliseconds = now;
                        //Console.Write(String.Format("{0,3}", DataHolder.ttl) + "\t" + String.Format("{0,5} ms", milliseconds) + "\t");
                        //Console.Write(String.Format("{0,3}", _TTL) + "\t" + String.Format("{0,5} ms", milliseconds) + "\t" );
                        Console.Write(String.Format("{0,3}", _TTL) + "\t" + String.Format("{0,5} ms", hrt_took) + "\t");

                        //Console.WriteLine(DataHolder.FormatIP(ip.Source.ToString()));
                        //Console.Write(DataHolder.FormatIP(DestinationIpV4.ToString()) + ":" + _PORT + "\t");
                        DataHolder.PrintIP(DestinationIpV4.ToString());
                        Console.Write(":" + _PORT + "\t");

                        Program.DebugPrint("... control bits:" + packet.Ethernet.IpV4.Tcp.ControlBits.ToString() );
                        if (packet.Ethernet.IpV4.Tcp.ControlBits.HasFlag(TcpControlBits.Synchronize) && packet.Ethernet.IpV4.Tcp.ControlBits.HasFlag(TcpControlBits.Acknowledgment))
                        {
                            Program.DebugPrint("... its a SYN/ACK");
                            //Console.WriteLine("SYN/ACK - port is open");
                            Console.WriteLine(packet.Ethernet.IpV4.Tcp.ControlBits.ToString() + " (port open)");

                            // its open, lets try and talk to it...
                            if (DataHolder.opt_do_http)
                            {
                                WaitForResponse(communicator);
                                return;
                            }
                            else
                            {
                                DataHolder.done = true;
                                return;
                            }
                        }

                        if (packet.Ethernet.IpV4.Tcp.ControlBits.HasFlag(TcpControlBits.Reset) && packet.Ethernet.IpV4.Tcp.ControlBits.HasFlag(TcpControlBits.Acknowledgment))
                        {
                            Program.DebugPrint("... its a RST/ACK");
                            //Console.WriteLine("RST/ACK - port is closed");
                            // its closed, so don't do the sendy thing
                            Console.WriteLine(packet.Ethernet.IpV4.Tcp.ControlBits.ToString() + " (port closed)");
                            DataHolder.done = true;
                            return;
                        }

                        //DataHolder.Responders = DataHolder.Responders + " " + ip.Source.ToString();
                        //DataHolder.state = 1;
                        //DataHolder.done = true;                        
                        //return;

                        // restart and get the amount of time to send the HTTP Get
                        DataHolder.sw.Restart();
                        DataHolder.hrt_start = DataHolder.hrt.Value;
                        //SendGet(communicator);
                        break;
                        


                    }

                    

                }
                // took this out to remove syn flood maybe it will still work

                if ((resendTimer.ElapsedMilliseconds > DataHolder.opt_wait_time) )
                {
                    
                    DataHolder.sw.Stop();
                    //long milliseconds = DataHolder.sw.ElapsedTicks / (System.Diagnostics.Stopwatch.Frequency / (1000L));
                    long milliseconds = DataHolder.sw.ElapsedMilliseconds;
                    DataHolder.hrt_stop = DataHolder.hrt.Value;

                    hrt_took = ((DataHolder.hrt_stop - DataHolder.hrt_start) * 1000) / DataHolder.hrt.Frequency;

                    //Console.WriteLine(String.Format("{0,3}", _TTL) + "\t" + String.Format("{0,5} ms", milliseconds) + "\ttimed out\t");
                    Console.WriteLine(String.Format("{0,3}", _TTL) + "\t" + String.Format("{0,5} ms", hrt_took) + "\ttimed out\t");
                    //return;

                    Program.DebugPrint("Timed out, current num_attempts is " + num_attempts.ToString() + " and rety times is " + DataHolder.opt_retry_times.ToString());
                    if (num_attempts < DataHolder.opt_retry_times)
                    {
                        num_attempts++;
                        //Console.WriteLine("Lost a packet, sending a new syn");
                        Program.DebugPrint("Lost a packet, sending a new syn...");
                        DataHolder.sw.Reset();
                        DataHolder.sw.Restart();
                        DataHolder.hrt_start = DataHolder.hrt.Value;
                        resendTimer.Reset();
                        resendTimer.Restart();
                        SendSyn(communicator);
                        //break;
                    }
                    else
                    {
                        return;
                    }
                }
            }
            //WaitForResponse(communicator);
        }

        private void WaitForResponse(PacketCommunicator communicator)
        {
            Int64 hrt_took;
            int num_attempts = 1;
            //Console.WriteLine("@@WaitForResponse");
            System.Diagnostics.Stopwatch resendTimer = new System.Diagnostics.Stopwatch();
            communicator.SetFilter("tcp and src " + DestinationIpV4 + " and dst " + SourceIpV4 + " and src port " + _PORT + " and dst port " + _sourcePort);
            //communicator.SetFilter("(tcp and src " + DestinationIpV4 + " and dst " + SourceIpV4 + " and src port " + _destinationPort + " and dst port " + _sourcePort + ") or (icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply)");
            Packet packet;
            resendTimer.Start();
            Console.WriteLine("\t\t\t(Sending HTTP GET...)");
            SendGet(communicator);
            while (true)
            {
                if (communicator.ReceivePacket(out packet) == PacketCommunicatorReceiveResult.Ok)
                {
                    Program.DebugPrint("Potential Packet received from communicator (HTTP response)...");
                    //Console.WriteLine("banana");
                    //Console.WriteLine("Expected ack number: " + _expectedAckNumber);
                    //Console.WriteLine("Received ack number: " + packet.Ethernet.IpV4.Tcp.AcknowledgmentNumber);
                    if (packet.Ethernet.IpV4.Tcp.AcknowledgmentNumber == _expectedAckNumber)
                    {
                        Program.DebugPrint("... packet is TCP with a matching ACK number");

                        _seqNumber = _expectedAckNumber;
                        _ackNumber = packet.Ethernet.IpV4.Tcp.SequenceNumber + 1;

                        DataHolder.sw.Stop();
                        //long milliseconds = DataHolder.sw.ElapsedTicks / (System.Diagnostics.Stopwatch.Frequency / (1000L));
                        long milliseconds = DataHolder.sw.ElapsedMilliseconds;

                        DataHolder.hrt_stop = DataHolder.hrt.Value;

                        hrt_took = ((DataHolder.hrt_stop - DataHolder.hrt_start) * 1000) / DataHolder.hrt.Frequency;

                        //Console.Write(String.Format("{0,3}", DataHolder.ttl) + "\t" + String.Format("{0,5} ms", milliseconds) + "\t");
                        //Console.Write(String.Format("{0,3}", _TTL) + "\t" + String.Format("{0,5} ms", milliseconds) + "\t");
                        Console.Write(String.Format("{0,3}", _TTL) + "\t" + String.Format("{0,5} ms", hrt_took) + "\t");

                        //Console.Write(DataHolder.FormatIP(DestinationIpV4.ToString()) + ":" + _PORT);
                        DataHolder.PrintIP(DestinationIpV4.ToString());
                        Console.Write(":" + _PORT + "\t");
                        //Console.WriteLine("\tHTTP GET acknowledged");

                        //Console.WriteLine(packet.Ethernet.IpV4.Tcp.ControlBits.ToString());
                        Console.WriteLine(packet.Ethernet.IpV4.Tcp.ControlBits.ToString());

                        //@@ zero bytes, so I bailed on this
                        //if (packet.Ethernet.IpV4.Tcp.ControlBits.HasFlag(TcpControlBits.Acknowledgment))
                        //{
                        //    Console.WriteLine(packet.Ethernet.IpV4.Tcp.Payload.ToString() );
                        //}

                        break;
                    }

                }
                //if ((resendTimer.ElapsedTicks / (System.Diagnostics.Stopwatch.Frequency / (1000L)) > 2000))
                if ((resendTimer.ElapsedMilliseconds > DataHolder.opt_wait_time))
                {
                    DataHolder.sw.Stop();
                    //long milliseconds = DataHolder.sw.ElapsedTicks / (System.Diagnostics.Stopwatch.Frequency / (1000L));
                    long milliseconds = DataHolder.sw.ElapsedMilliseconds;
                    DataHolder.hrt_stop = DataHolder.hrt.Value;

                    hrt_took = ((DataHolder.hrt_stop - DataHolder.hrt_start) * 1000) / DataHolder.hrt.Frequency;
                    //Console.WriteLine(String.Format("{0,3}", _TTL) + "\t" + String.Format("{0,5} ms", milliseconds) + "\ttimed out\t");
                    Console.WriteLine(String.Format("{0,3}", _TTL) + "\t" + String.Format("{0,5} ms", hrt_took) + "\ttimed out\t");
                    //return;

                    //Console.WriteLine("Lost a packet, sending a new syn");
                    //DataHolder.sw.Reset();
                    //DataHolder.sw.Restart();
                    //resendTimer.Reset();
                    //resendTimer.Restart();
                    //SendSyn(communicator);
                    //break;
                    Program.DebugPrint("Timed out, current num_attempts is " + num_attempts.ToString() + " and retry times is " + DataHolder.opt_retry_times.ToString());
                    if (num_attempts < DataHolder.opt_retry_times)
                    {
                        num_attempts++;
                        //Console.WriteLine("Lost a packet, sending a new syn");
                        Program.DebugPrint("Lost a packet, sending a new syn...");
                        DataHolder.sw.Reset();
                        DataHolder.sw.Restart();
                        DataHolder.hrt_start = DataHolder.hrt.Value;
                        resendTimer.Reset();
                        resendTimer.Restart();
                        SendSyn(communicator);
                        //break;
                    }
                    else
                    {
                        return;
                    }
                }
                //SendGet(communicator);
                
            }
            SendFin(communicator);
            DataHolder.done = true;
        }

        private void SendFin(PacketCommunicator communicator)
        {
            Program.DebugPrint("sending FIN");
            //Console.WriteLine("@@SendSyn");
            // Ethernet Layer
            EthernetLayer ethernetLayer = new EthernetLayer
            {
                Source = SourceMac,
                Destination = DestinationMac,
            };

            // IPv4 Layer
            IpV4Layer ipV4Layer = new IpV4Layer
            {
                Source = SourceIpV4,
                CurrentDestination = DestinationIpV4,
                //Ttl = 128,
                Ttl = Convert.ToByte(_TTL),
                Fragmentation =
                    new IpV4Fragmentation(IpV4FragmentationOptions.DoNotFragment, 0),
                Identification = 1234,
            };

            // TCP Layer
            TcpLayer tcpLayer = new TcpLayer
            {
                SourcePort = _sourcePort,
                DestinationPort = _PORT,
                SequenceNumber = _seqNumber,
                ControlBits = TcpControlBits.Fin,
                Window = _windowSize,
            };
            //Console.WriteLine("sending a packet");
            communicator.SendPacket(PacketBuilder.Build(DateTime.Now, ethernetLayer, ipV4Layer, tcpLayer));
            _expectedAckNumber = _seqNumber + 1;
        }

        private void SendSyn(PacketCommunicator communicator)
        {
            Program.DebugPrint("sending SYN");
            //Console.WriteLine("@@SendSyn");
            // Ethernet Layer
            EthernetLayer ethernetLayer = new EthernetLayer
            {
                Source = SourceMac,
                Destination = DestinationMac,
            };

            // IPv4 Layer
            IpV4Layer ipV4Layer = new IpV4Layer
            {
                Source = SourceIpV4,
                CurrentDestination = DestinationIpV4,
                //Ttl = 128,
                Ttl = Convert.ToByte(_TTL),
                Fragmentation =
                    new IpV4Fragmentation(IpV4FragmentationOptions.DoNotFragment, 0),
                Identification = 1234,
            };

            // TCP Layer
            TcpLayer tcpLayer = new TcpLayer
            {
                SourcePort = _sourcePort,
                DestinationPort = _PORT,
                SequenceNumber = _seqNumber,
                ControlBits = TcpControlBits.Synchronize,
                Window = _windowSize,
            };
            //Console.WriteLine("sending a packet");
            communicator.SendPacket(PacketBuilder.Build(DateTime.Now, ethernetLayer, ipV4Layer, tcpLayer));
            _expectedAckNumber = _seqNumber + 1;
        }

        private void SendGet(PacketCommunicator communicator)
        {
            Program.DebugPrint("sending SYN (http get mode)");
            //Console.WriteLine("@@SendGet");
            // Ethernet Layer
            EthernetLayer ethernetLayer = new EthernetLayer
            {
                Source = SourceMac,
                Destination = DestinationMac,
            };

            // IPv4 Layer
            IpV4Layer ipV4Layer = new IpV4Layer
            {
                Source = SourceIpV4,
                CurrentDestination = DestinationIpV4,
                Ttl = Convert.ToByte(_TTL),
                Fragmentation =
                    new IpV4Fragmentation(IpV4FragmentationOptions.DoNotFragment, 0),
                Identification = 1235,
            };

            // TCP Layer
            TcpLayer tcpLayer = new TcpLayer
            {
                SourcePort = _sourcePort,
                DestinationPort = _PORT,
                SequenceNumber = _seqNumber,
                AcknowledgmentNumber = _ackNumber,
                ControlBits = TcpControlBits.Acknowledgment,
                //ControlBits = TcpControlBits.Acknowledgment|TcpControlBits.Fin,
                Window = _windowSize,
            };

            // HTTP Layer
            HttpLayer httpLayer = new HttpRequestLayer
            {
                Uri = "/",
                Header = new HttpHeader(HttpField.CreateField("Host", Host)),
                Method = new HttpRequestMethod(HttpRequestKnownMethod.Get),
                Version = PcapDotNet.Packets.Http.HttpVersion.Version11,
            };
            //Console.WriteLine("sending a get packet");
            Packet packet = PacketBuilder.Build(DateTime.Now, ethernetLayer, ipV4Layer, tcpLayer, httpLayer);
            communicator.SendPacket(packet);
            _expectedAckNumber = (uint)(_seqNumber + packet.Ethernet.IpV4.Tcp.PayloadLength);
        }

        private ushort _sourcePort = (ushort)(4123 + new Random().Next() % 1000);
        //private ushort _destinationPort = _PORT;
        private uint _seqNumber = (uint)new Random().Next();
        private uint _expectedAckNumber;
        private ushort _windowSize = 8192;
        private uint _ackNumber;
    }
}
