using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;
using System.Xml.Schema;

namespace ksis1
{
    internal class Program
    {
        
        public static void ShowNetworkInterfaces()
        {
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
            
            if (nics == null || nics.Length < 1)
            {
                Console.WriteLine("  No network interfaces found.");
                return;
            }

            int num = 0;
            Console.WriteLine("  Number of interfaces: {0}", nics.Length);
            foreach (NetworkInterface adapter in nics)
            {
                Console.WriteLine(num+"   " + adapter.Description);
                Console.WriteLine("  Interface type: {0}", adapter.NetworkInterfaceType);
                Console.Write("  Physical address: ");
                Console.WriteLine(getStrMac(adapter.GetPhysicalAddress()));
                foreach (UnicastIPAddressInformation ip in adapter.GetIPProperties().UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        //Console.WriteLine();
                        Console.Write("  IP address: {0}", ip.Address.ToString());
                        Console.Write("  Mask: {0}", ip.IPv4Mask.ToString());
                    }
                }
                Console.WriteLine();
                Console.WriteLine("_______________________________");
                num++;
            }
            
            Console.WriteLine("Select interface: ");
            var input = Console.ReadLine();
            if( Int32.TryParse(input, out int selected) && selected >= 0 && selected < nics.Length);
            try
            {
                 var ip = nics[selected].GetIPProperties().UnicastAddresses
                    .First(x => x.Address.AddressFamily == AddressFamily.InterNetwork);
                 
                Scan(ip.Address, IpToInt(ip.IPv4Mask), getStrMac(nics[selected].GetPhysicalAddress()));
            }
            catch(PingException)
            {
                Console.WriteLine("Try other interface");
            }
           
        }

        public static string getStrMac(PhysicalAddress macAddr)
        {
            string res = "";
            byte[] bytes = macAddr.GetAddressBytes();
            for(int i = 0; i< bytes.Length; i++)
            {
                res += bytes[i].ToString("X2");
                if (i != bytes.Length -1)
                {
                    res += '-';
                }
            }

            return res;
        }

        public class ThreadWithState
        {
            private IPAddress address;
            private IPAddress hostIp;
            private string mac;

            public ThreadWithState(IPAddress addressP, IPAddress hostIpP, string macP)
            {
                address = addressP;
                hostIp = hostIpP;
                mac = macP;
            }

            public void TryPing()
            {
                PingReply pingReply;
                using (var pinger = new Ping())
                {
                    pingReply = pinger.Send(address, 500);
                }

                if (!address.Equals(hostIp))
                {
                    mac = CheckArpTable(address.ToString());
                }
            

                if (pingReply.Status == IPStatus.Success)
                {
                    Console.Write($"Ping: Success, ip: {address}");
                    if (mac != null)
                    {
                        Console.WriteLine($", mac: {mac}");
                    }
                    else
                    {
                        Console.WriteLine();
                    }
                }
                else 
                {
                    Console.Write($"Ping: Failed, ip: {address}");
                    if (mac != null)
                    {
                        Console.WriteLine($", mac: {mac}");
                    }
                    else
                    {
                        Console.WriteLine();
                    }
                }
            }
        }
        public static void Scan(IPAddress ip, int mask, string hostMac)
        {
            int ipInt = IpToInt(ip);
            var firstAddress = ipInt & mask;
            var numOfAddr = ~mask - 1;
            Thread[] threads = new Thread[8];
            int k = 0;
            for (int i = 1; i <= numOfAddr; i++)
            {
                var checkedAddress = firstAddress + i;
                var checkedIP = IntToIp(checkedAddress);
                var inetAddress = IPAddress.Parse(checkedIP);
                  ThreadWithState tws = new ThreadWithState(inetAddress, ip, hostMac);
                if (k < 8)
                {
                    threads[k] = new Thread(new ThreadStart(tws.TryPing));
                    threads[k].Start();
                    k++;
                }
                else
                {
                    for(int j = 0; j<8; j++)
                    {
                        threads[j].Join();
                    }
                    threads[0] = new Thread(new ThreadStart(tws.TryPing));
                    threads[0].Start();
                    k = 1;
                }
                //  TryPing(inetAddress, ip, hostMac);
            }
            
            
        }

        

        private static void TryPing(IPAddress address, IPAddress hostIp, string mac)
        {
            PingReply pingReply;
            using (var pinger = new Ping())
            {
                pingReply = pinger.Send(address, 500);
            }

            if (!address.Equals(hostIp))
            {
                mac = CheckArpTable(address.ToString());
            }
            

            if (pingReply.Status == IPStatus.Success)
            {
                Console.Write($"Ping: Success, ip: {address}");
                if (mac != null)
                {
                    Console.WriteLine($", mac: {mac}");
                }
                else
                {
                    Console.WriteLine();
                }
            }
            else 
            {
                Console.Write($"Ping: Failed, ip: {address}");
                if (mac != null)
                {
                    Console.WriteLine($", mac: {mac}");
                }
                else
                {
                    Console.WriteLine();
                }
            }
        }
        
        private static string IntToIp(int addr)
        {
            short[] buf = new short[4];
            short check = 255;
            buf[3] = (short)(addr & check);
            buf[2] = (short)((addr >> 8) & check);
            buf[1] = (short)((addr >> 16) & check);
            buf[0] = (short)((addr >> 24) & check);
            return $"{buf[0]}.{buf[1]}.{buf[2]}.{buf[3]}";
        }
        
        private static int IpToInt(IPAddress addr)
        {
            byte[] ip = addr.GetAddressBytes();
            int res = 0;
            for (int i = 0; i < 4; i++)
            {
                res += ip[i] * (int)Math.Pow(256,3-i);
            }
            return res;
        }
        
        private static string CheckArpTable(string ip)
        {
            string systemInput;
            
            using (var process = new Process())
            {
                process.StartInfo.FileName = "arp";
                process.StartInfo.Arguments = "-a " + ip;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.Start();
                systemInput = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
            } 
            string mac = null;
            var reg = new Regex(@"\s*([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})");
            var match = reg.Match(systemInput);
            if (match.Success)
            {
                mac = match.Value.Replace(" ", "");
            }

            return mac;
        }
        
        public static void Main(string[] args)
        {
            ShowNetworkInterfaces();
        }
    }
}