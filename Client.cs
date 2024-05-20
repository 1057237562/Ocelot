using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Ocelot
{

    class Client
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        RSACryptoServiceProvider en = new RSACryptoServiceProvider();
        int threadCnt = 0;
        Mutex mutex = new Mutex();
        public Client(string sip, int sport, int port)
        {
            Console.WriteLine("Proxy listening at : " + port);
            var listener = new TcpListener(IPAddress.Parse("0.0.0.0"), port);
            var aes = Aes.Create();
            using (var link = new TcpClient(sip, sport))
            {
                Handshake(link.GetStream(), aes);
            }
            listener.Start();

            while (true)
            {
                var soft = listener.AcceptTcpClient();

                var src = soft.GetStream();
                threadCnt++;
                try { Console.Clear(); } catch (Exception) { }
                Console.Error.WriteLine("Current alive connection count:" + threadCnt);
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    try
                    {
                        int version = Util.certificate(src);
                        if (version == 0)
                        {
                            mutex.WaitOne();

                            threadCnt--;
                            try { Console.Clear(); }catch (Exception) { }
                            Console.Error.WriteLine("Current alive connection count:" + threadCnt);

                            mutex.ReleaseMutex();
                            Console.WriteLine("Failed in certificating");
                            return;
                        }
                        int rport;
                        using (var ctl = new TcpClient(sip, sport))
                        {
                            rport = Request(ctl.GetStream());
                        }
                        using var alloc = new TcpClient(sip, rport);

                        if (Program.log)
                            Console.WriteLine("Relaying " + soft.Client.RemoteEndPoint!.ToString() + " to " + alloc!.Client.RemoteEndPoint!.ToString());
                        using var astream = alloc.GetStream();
                        using var dst = new EncryptNetworkStream(astream, aes.CreateEncryptor(), aes.CreateDecryptor());

                        if (version == 4)
                        {
                            byte[] request = new byte[6];
                            src.FRead(request, 0, 6);
                            dst.Write(Socks.convertToSocks5(request));
                            while (src.ReadByte() != 0) ;
                        }
                        if(version == 1)
                        {
                            byte[] request = new byte[8192];
                            int n = src.Read(request, 0, 8192);
                            while (request[n - 1] != 0x0A || request[n - 3] != 0x0A)
                            {
                                n += src.Read(request, n, 8192 - n);
                            }
                            dst.Write(Http.convertToSocks5(Encoding.ASCII.GetString(request.ToArray(), 0, n)));
                            src.Write(Http.connectionSucceed());

                        }

                        HandleStream(src, dst);

                        if (Program.log)
                            Console.WriteLine("Closing " + soft.Client.RemoteEndPoint!.ToString() + " to " + alloc!.Client.RemoteEndPoint!.ToString());

                    }
                    catch (Exception e) { Console.Error.WriteLine(e); }
                    mutex.WaitOne();

                    threadCnt--;
                    try { Console.Clear(); } catch (Exception) { }
                    Console.Error.WriteLine("Current alive connection count:" + threadCnt);

                    mutex.ReleaseMutex();
                    src.Dispose();
                    soft.Dispose();
                });
            }
        }

        public int Request(Stream stream)
        {
            stream.WriteByte(1);
            byte[] token = en.Encrypt(Encoding.ASCII.GetBytes(Program.user + "\n" + Program.pass), true);
            stream.Write(BitConverter.GetBytes(token.Length));
            stream.Write(token);

            byte[] buf = new byte[4];
            stream.FRead(buf, 0, 4);
            int len = BitConverter.ToInt32(buf, 0);
            byte[] data = new byte[len];
            stream.FRead(data, 0, len);
            return BitConverter.ToInt32(rsa.Decrypt(data,true));
        }

        public void Handshake(Stream stream, SymmetricAlgorithm sa)
        {
            stream.WriteByte(0);
            byte[] buf = new byte[4];
            stream.FRead(buf, 0, 4);
            int len = BitConverter.ToInt32(buf, 0);
            byte[] data = new byte[len];
            stream.FRead(data, 0, len);
            
            en.ImportSubjectPublicKeyInfo(data, out _);

            byte[] decrypt = rsa.ExportSubjectPublicKeyInfo();
            stream.Write(BitConverter.GetBytes(decrypt.Length));
            stream.Write(decrypt);

            byte[] token = en.Encrypt(Encoding.ASCII.GetBytes(Program.user + "\n" + Program.pass),true);
            stream.Write(BitConverter.GetBytes(token.Length));
            stream.Write(token);

            stream.FRead(buf, 0, 4);
            len = BitConverter.ToInt32(buf, 0);
            data = new byte[len];
            stream.FRead(data, 0, len);
            sa.Key = rsa.Decrypt(data, true);
            stream.FRead(buf, 0, 4);
            len = BitConverter.ToInt32(buf, 0);
            data = new byte[len];
            stream.FRead(data, 0, len);
            sa.IV = rsa.Decrypt(data, true);
        }

        public void HandleStream(Stream src, Stream dst)
        {
            ThreadPool.QueueUserWorkItem(_ => { try { dst.CopyTo(src); } catch (Exception) { } src.TryClose(); });
            try { src.CopyTo(dst); } catch (Exception) { }
            dst.TryClose();
        }

    }
}
