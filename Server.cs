using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Ocelot
{
    class Server
    {

        Dictionary<string, UserToken> keyValuePairs = new Dictionary<string, UserToken>();
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

        public Server(int port)
        {
            var listener = new TcpListener(IPAddress.Parse("0.0.0.0"), port);
            var aes = Aes.Create();
            if(aes == null)
            {
                Console.WriteLine("Failed in creating Crypto Instance.");
                return;
            }
            listener.Start();
            if (Program.log)
                Console.WriteLine("Server started at : " + port);
            while (true)
            {
                using var client = listener.AcceptTcpClient();
                using var link = client.GetStream();

                if (Program.log)
                    Console.WriteLine("Incomming Transmittion : " + client.Client.RemoteEndPoint!.ToString());
                try
                {
                    if (link.ReadByte() == 0)
                    {
                        Handshake(link, aes);
                    }
                    else
                    {
                        var transmit = new TcpListener(IPAddress.Any, 0);
                        transmit.Start();

                        if (Program.log)
                            Console.WriteLine("Open repeater on port : " + ((IPEndPoint)transmit.LocalEndpoint!).Port);
                        try
                        {
                            var token = Respond(link, aes);
                            byte[] pb = token.encrypt.Encrypt(BitConverter.GetBytes(((IPEndPoint)transmit.LocalEndpoint!).Port), true);
                            link.Write(BitConverter.GetBytes(pb.Length));
                            link.Write(pb);
                            var th = new Thread(() =>
                            {
                                using (var incoming = transmit.AcceptTcpClient())
                                {
                                    using var istream = incoming.GetStream();
                                    using var dst = new EncryptNetworkStream(istream, aes.CreateEncryptor(), aes.CreateDecryptor()); ;
                                    try { Socks.handle(dst); } catch (Exception) { }
                                }
                                transmit.Stop();
                            });
                            th.IsBackground = true;
                            th.Start();
                        }
                        catch (Exception e) { transmit.Stop(); Console.Error.WriteLine(e); }
                    }
                }
                catch (Exception e) { Console.Error.WriteLine(e); }
            }
        }

        public UserToken Respond(Stream stream, SymmetricAlgorithm sa)
        {
            byte[] buf = new byte[4];
            stream.FRead(buf, 0, 4);
            int len = BitConverter.ToInt32(buf, 0);
            byte[] data = new byte[len];
            stream.FRead(data, 0, len);

            byte[] userToken = rsa.Decrypt(data, true);
            string ut = BitConverter.ToString(userToken);
            sa.Key = keyValuePairs[ut].key;
            sa.IV = keyValuePairs[ut].iv;
            return keyValuePairs[ut];
        }

        public void Handshake(Stream stream, SymmetricAlgorithm sa)
        {
            RSACryptoServiceProvider en = new RSACryptoServiceProvider();

            byte[] encrypt = rsa.ExportSubjectPublicKeyInfo();
            stream.Write(BitConverter.GetBytes(encrypt.Length));
            stream.Write(encrypt);
            
            byte[] buf = new byte[4];
            stream.FRead(buf, 0, 4);
            int len = BitConverter.ToInt32(buf, 0);
            byte[] data = new byte[len];
            stream.FRead(data,0, len);
            en.ImportSubjectPublicKeyInfo(data, out _);

            stream.FRead(buf, 0, 4);
            len = BitConverter.ToInt32(buf, 0);
            data = new byte[len];
            stream.FRead(data, 0, len);
            byte[] userToken = rsa.Decrypt(data, true);

            sa.GenerateKey();
            sa.GenerateIV();
            UserToken kp = new UserToken(en, sa.Key, sa.IV);
            byte[] encryptKey = en.Encrypt(sa.Key, true);
            stream.Write(BitConverter.GetBytes(encryptKey.Length));
            stream.Write(encryptKey);
            byte[] encryptIV = en.Encrypt(sa.IV, true);
            stream.Write(BitConverter.GetBytes(encryptIV.Length));
            stream.Write(encryptIV);

            keyValuePairs[BitConverter.ToString(userToken)] = kp;
        }
    }
}
