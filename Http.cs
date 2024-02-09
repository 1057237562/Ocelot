using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Ocelot
{
    class Http
    {
        public static byte[] convertToSocks5(string request)
        {
            string url = request.Split(' ')[0];
            byte[] hostname = Encoding.UTF8.GetBytes(url.Split(':')[0]);
            ushort port = ushort.Parse(url.Split(':')[1]);
            byte[] data = new byte[5 + hostname.Length + 2];
            data[3] = 0x03;
            data[4] = (byte)hostname.Length;
            hostname.CopyTo(data, 5);
            data[5 + hostname.Length] = (byte)(port >> 8);
            data[5 + hostname.Length + 1] = (byte)port;
            return data;
        }

        public static ReadOnlySpan<byte> connectionSucceed()
        {
            string resp = "HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n";
            return Encoding.ASCII.GetBytes(resp);
        }
    }
}
