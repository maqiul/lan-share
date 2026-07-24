using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace LanShareMount.Network
{
    /// <summary>
    /// Minimal RFC 6455 WebSocket client. Works on .NET Framework 2.0+.
    /// Only enough features to talk to the LanShare server's /wsp endpoint.
    /// </summary>
    public sealed class WebSocket : IDisposable
    {
        TcpClient _tcp;
        NetworkStream _stream;
        string _host;
        int _port;
        string _path;

        public WebSocket(string host, int port, string path = "/wsp")
        {
            _host = host;
            _port = port;
            _path = path;
        }

        public void Connect(string authHeader = null)
        {
            _tcp = new TcpClient();
            _tcp.NoDelay = true;
            _tcp.Connect(_host, _port);
            _stream = _tcp.GetStream();

            var keyBytes = new byte[16];
            var rng = new Random();
            for (int i = 0; i < keyBytes.Length; i++) keyBytes[i] = (byte)rng.Next(256);
            string secKey = Convert.ToBase64String(keyBytes);

            var req = new StringBuilder();
            req.Append("GET ").Append(_path).Append(" HTTP/1.1\r\n");
            req.Append("Host: ").Append(_host).Append(":").Append(_port).Append("\r\n");
            req.Append("Upgrade: websocket\r\n");
            req.Append("Connection: Upgrade\r\n");
            req.Append("Sec-WebSocket-Key: ").Append(secKey).Append("\r\n");
            req.Append("Sec-WebSocket-Version: 13\r\n");
            if (authHeader != null)
                req.Append("Authorization: ").Append(authHeader).Append("\r\n");
            req.Append("\r\n");

            var reqBytes = Encoding.ASCII.GetBytes(req.ToString());
            _stream.Write(reqBytes, 0, reqBytes.Length);
            _stream.Flush();

            // Read HTTP response headers (parse line by line)
            var headerBuf = new StringBuilder();
            var oneByte = new byte[1];
            int matched = 0;
            while (matched < 4)
            {
                int n = _stream.Read(oneByte, 0, 1);
                if (n <= 0) throw new IOException("Server closed during WebSocket handshake");
                char c = (char)oneByte[0];
                if (c == "\r\n\r\n"[matched]) matched++;
                else matched = 0;
                headerBuf.Append(c);
            }
            var headers = headerBuf.ToString();
            if (!headers.Contains(" 101 "))
                throw new IOException("WebSocket upgrade failed: " + headers.Split('\n')[0]);
        }

        /// <summary>Send a binary frame (opcode 0x2).</summary>
        public void SendBinary(byte[] data)
        {
            // We only ever send small frames (≤ MAX_PAYLOAD 4MB)
            var header = new List<byte>();
            header.Add(0x82); // FIN + binary

            int len = data.Length;
            if (len < 126)
            {
                header.Add((byte)len);
            }
            else if (len <= 0xFFFF)
            {
                header.Add(126);
                header.Add((byte)(len >> 8));
                header.Add((byte)(len & 0xFF));
            }
            else
            {
                header.Add(127);
                for (int i = 7; i >= 0; i--)
                    header.Add((byte)((len >> (8 * i)) & 0xFF));
            }

            // client must mask
            var mask = new byte[4];
            new Random().NextBytes(mask);
            header.AddRange(mask);

            _stream.Write(header.ToArray(), 0, header.Count);
            for (int i = 0; i < len; i++)
                data[i] ^= mask[i % 4];
            _stream.Write(data, 0, len);
            _stream.Flush();
        }

        /// <summary>Receive a single binary frame (opcode 0x2) or text (0x1). Returns the unmasked payload, or null on close.</summary>
        public byte[] Receive()
        {
            // Read 2-byte header
            int h0 = _stream.ReadByte();
            int h1 = _stream.ReadByte();
            if (h0 < 0 || h1 < 0) return null;

            bool fin = (h0 & 0x80) != 0;
            int opcode = h0 & 0x0F;
            bool masked = (h1 & 0x80) != 0;
            long len = h1 & 0x7F;

            if (opcode == 0x8) return null; // close

            if (len == 126)
            {
                int b1 = _stream.ReadByte();
                int b2 = _stream.ReadByte();
                len = (b1 << 8) | b2;
            }
            else if (len == 127)
            {
                long l = 0;
                for (int i = 0; i < 8; i++)
                    l = (l << 8) | (uint)_stream.ReadByte();
                len = l;
            }

            byte[] mask = null;
            if (masked)
            {
                mask = new byte[4];
                for (int i = 0; i < 4; i++) mask[i] = (byte)_stream.ReadByte();
            }

            if (len > 32 * 1024 * 1024)
                throw new IOException("WebSocket frame too large: " + len);

            var buf = new byte[len];
            int read = 0;
            while (read < len)
            {
                int n = _stream.Read(buf, read, (int)(len - read));
                if (n <= 0) throw new IOException("WebSocket truncated read");
                read += n;
            }

            if (mask != null)
            {
                for (int i = 0; i < buf.Length; i++)
                    buf[i] ^= mask[i % 4];
            }

            // continuation frames: assume server doesn't fragment
            return buf;
        }

        public void Close()
        {
            if (_stream != null)
            {
                try
                {
                    var close = new byte[] { 0x88, 0x80, 0, 0, 0, 0 };
                    _stream.Write(close, 0, close.Length);
                    _stream.Flush();
                }
                catch { }
                _stream.Dispose();
                _stream = null;
            }
            if (_tcp != null)
            {
                try { _tcp.Close(); } catch { }
                _tcp = null;
            }
        }

        public void Dispose() { Close(); }
    }
}