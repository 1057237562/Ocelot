using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Ocelot
{
    class EncryptNetworkStream : Stream
    {
        NetworkStream network;
        ICryptoTransform encrypt;
        ICryptoTransform decrypt;

        MemoryStream bms;
        public long traffic = 0;

        byte[] t = new byte[16];

        public EncryptNetworkStream(NetworkStream stream, ICryptoTransform encrypt,ICryptoTransform decrypt)
        {
            network = stream;
            this.encrypt = encrypt;
            this.decrypt = decrypt;

            bms = new MemoryStream();
            bms.SetLength(0);
        }

        public override bool CanRead => network.CanRead;

        public override bool CanSeek => network.CanSeek;

        public override bool CanWrite => network.CanWrite;

        public override long Length => network.Length;

        public override long Position { get; set; }

        public override void Flush()
        {
            network.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            try
            {
                if (bms.Position >= bms.Length)
                {
                    network.FRead(t, 0, 16);
                    int len = BitConverter.ToInt32(decrypt.TransformFinalBlock(t, 0, 16), 0);
                    byte[] data = new byte[len];
                    network.FRead(data, 0, len);
                    bms.Dispose();
                    bms = new MemoryStream(decrypt.TransformFinalBlock(data, 0, len));
                    traffic += 16 + len;
                }
                return bms.Read(buffer, offset, count);
            }catch(Exception) {
                return 0;
            }
        }


        public override long Seek(long offset, SeekOrigin origin) => 0;

        public override void SetLength(long value) { }

        public override void Write(byte[] buffer, int offset, int count)
        {
            try
            {
                byte[] data = encrypt.TransformFinalBlock(buffer, offset, count);
                network.Write(encrypt.TransformFinalBlock(BitConverter.GetBytes(data.Length), 0, 4));
                network.Write(data);
                traffic += 16 + data.Length;
            }catch(Exception) {
            }
        }

        public override void Close()
        {
            base.Close();
            bms.Dispose();
        }
    }
}
