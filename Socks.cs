using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Ocelot
{
    class Socks
    {
        public struct Address
        {
            public string hostname;
            public int port;
        }

        public static byte[] convertToSocks5(byte[] socks4quest) {
            byte[] buffer = new byte[10];
            buffer[3] = 0x01;
            for(int i = 4; i < 8; i++)
            {
                buffer[i] = socks4quest[i - 2];
            }
            buffer[8] = socks4quest[0];
            buffer[9] = socks4quest[1];
            return buffer;

        }
        public static Address parseDst(Stream stream)
        {
            byte[] buffer = new byte[256];
            stream.FRead(buffer, 0, 4);
            var res = new Address();
            switch (buffer[3])
            {
                case 0x01:
                    stream.FRead(buffer, 0, 4);
                    res.hostname = new IPAddress(new byte[]{ buffer[0], buffer[1], buffer[2], buffer[3] }).ToString();
                    break;
                case 0x03:
                    stream.FRead(buffer, 0, 1);
                    int size = buffer[0];
                    stream.FRead(buffer,0,size);
                    res.hostname = Encoding.UTF8.GetString(buffer, 0, size);
                    break;
                case 0x04:
                    stream.FRead(buffer, 0, 16);
                    res.hostname = new IPAddress(buffer.Take(16).ToArray()).ToString();
                    break;
            }
            stream.FRead(buffer, 0, 2);
            res.port = buffer[0] << 8 | buffer[1];
            return res;
        }
        public static void handle(Stream stream)
        {
            Address ipaddr = parseDst(stream);
            using var connect = new TcpClient(ipaddr.hostname, ipaddr.port);
            using var result = connect.GetStream();

            var th = new Thread(() => { try { stream.CopyTo(result); } catch (Exception) { } result.TryClose(); });
            th.IsBackground = true;
            th.Start();
            try { result.CopyTo(stream); } catch (Exception) { }
            th.Interrupt();
        }
    }
}
