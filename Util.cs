using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Ocelot
{
    public class User : IComparable<User>, IEquatable<User>
    {
        public string Name;
        public string Password;

        public User(string name, string password)
        {
            Name = name;
            Password = password;
        }

        public int CompareTo(User? other)
        {
            return (Name + Password).GetHashCode() - (other!.Name + other!.Password).GetHashCode();
        }

        public bool Equals(User? other)
        {
            return Name == other!.Name && Password == other!.Password;
        }
    }

    public struct UserToken
    {
        public RSACryptoServiceProvider encrypt;
        public byte[] key;
        public byte[] iv;

        public UserToken(RSACryptoServiceProvider en, byte[] k, byte[] i)
        {
            encrypt = en;
            key = k;
            iv = i;
        }
    }

    static class Util
    {
        public static void FRead(this Stream stream, byte[] data, int offset, int count)
        {
            int tot = stream.Read(data, offset, count);
            int n = tot;
            while (tot < count)
            {
                if (n == 0) throw new EndOfStreamException();
                n = stream.Read(data, offset + tot, count - tot);
                tot += n;
            }
        }

        public static void TryClose(this Stream stream)
        {
            try { stream.Close(); } catch (Exception) { }
        }

        public static void TryClose(this TcpClient client)
        {
            try { client.Close(); } catch (Exception) { }
        }

        public static void TryDispose(this Stream stream)
        {
            try { stream.Dispose(); } catch (Exception) { }
        }

        public static int certificate(Stream stream)
        {
            byte[] buffer = new byte[2];
            stream.FRead(buffer, 0, 2);
            if (buffer[0] == 0x05)
            {
                stream.FRead(buffer, 0, buffer[1]);

                stream.Write(new byte[] { 0x05, 0x00 });

                stream.Write(new byte[] { 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                stream.Flush();
                return 5;
            }
            if (buffer[0] == 0x04)
            {
                stream.Write(new byte[] { 0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                stream.Flush();
                return 4;
            }
            if (buffer[0] == 0x43 && buffer[1] == 0x4F)
            {
                buffer = new byte[6];
                stream.FRead(buffer, 0, 6);
                if (buffer[0] == 0x4E && buffer[1] == 0x4E && buffer[2] == 0x45 && buffer[3] == 0x43 && buffer[4] == 0x54)
                    return 1;
                else
                    return 0;
            }
            return 0;
        }
    }
}
