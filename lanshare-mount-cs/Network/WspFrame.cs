using System;
using System.IO;

namespace LanShareMount.Network
{
    /// <summary>
    /// WSP frame codec — 16-byte header + payload.
    ///   [0..2]   magic       0x57 0x53 ("WS")
    ///   [2]      version     0x01
    ///   [3]      msg_type    message type
    ///   [4..8]   stream_id   u32 BE
    ///   [8..12]  seq_num     u32 BE
    ///   [12..16] payload_len u32 BE
    ///   [16..]   payload
    /// </summary>
    public sealed class WspFrame
    {
        public const int HeaderLen = 16;
        public const byte Magic1 = 0x57;
        public const byte Magic2 = 0x53;
        public const byte Version = 0x01;

        public byte MsgType;
        public uint StreamId;
        public uint SeqNum;
        public byte[] Payload;

        public WspFrame() { Payload = new byte[0]; }

        public WspFrame(byte type, uint streamId, uint seq, byte[] payload)
        {
            MsgType = type;
            StreamId = streamId;
            SeqNum = seq;
            Payload = payload ?? new byte[0];
        }

        public byte[] Encode()
        {
            int total = HeaderLen + Payload.Length;
            var buf = new byte[total];
            buf[0] = Magic1;
            buf[1] = Magic2;
            buf[2] = Version;
            buf[3] = MsgType;
            WriteUInt32BE(buf, 4, StreamId);
            WriteUInt32BE(buf, 8, SeqNum);
            WriteUInt32BE(buf, 12, (uint)Payload.Length);
            Buffer.BlockCopy(Payload, 0, buf, HeaderLen, Payload.Length);
            return buf;
        }

        public static WspFrame Decode(byte[] data)
        {
            if (data == null || data.Length < HeaderLen)
                throw new InvalidDataException("frame too short");
            if (data[0] != Magic1 || data[1] != Magic2)
                throw new InvalidDataException("bad magic");
            if (data[2] != Version)
                throw new InvalidDataException("unsupported version " + data[2]);

            var f = new WspFrame
            {
                MsgType = data[3],
                StreamId = ReadUInt32BE(data, 4),
                SeqNum = ReadUInt32BE(data, 8),
            };
            uint plen = ReadUInt32BE(data, 12);
            if (plen > 4 * 1024 * 1024)
                throw new InvalidDataException("payload too large " + plen);
            if (HeaderLen + plen != data.Length)
                throw new InvalidDataException("payload length mismatch");

            f.Payload = new byte[plen];
            if (plen > 0)
                Buffer.BlockCopy(data, HeaderLen, f.Payload, 0, (int)plen);
            return f;
        }

        public string PayloadAsString()
        {
            return System.Text.Encoding.UTF8.GetString(Payload);
        }

        public static byte[] WriteJson(string json)
        {
            return System.Text.Encoding.UTF8.GetBytes(json);
        }

        static void WriteUInt32BE(byte[] buf, int offset, uint v)
        {
            buf[offset]     = (byte)(v >> 24);
            buf[offset + 1] = (byte)(v >> 16);
            buf[offset + 2] = (byte)(v >> 8);
            buf[offset + 3] = (byte)v;
        }

        static uint ReadUInt32BE(byte[] buf, int offset)
        {
            return ((uint)buf[offset] << 24)
                 | ((uint)buf[offset + 1] << 16)
                 | ((uint)buf[offset + 2] << 8)
                 |  (uint)buf[offset + 3];
        }
    }

    /// <summary>WSP message types (mirror of server's wsp.rs).</summary>
    public static class MsgType
    {
        public const byte Hello     = 0x01;
        public const byte HelloAck  = 0x02;
        public const byte Auth      = 0x03;
        public const byte AuthAck   = 0x04;

        public const byte ListDir      = 0x10;
        public const byte ListDirResp  = 0x11;
        public const byte Stat         = 0x12;
        public const byte StatResp     = 0x13;
        public const byte Mkdir        = 0x14;
        public const byte Rename       = 0x15;
        public const byte Delete       = 0x16;
        public const byte OpAck        = 0x17;

        public const byte UploadStart = 0x20;
        public const byte UploadData  = 0x21;
        public const byte UploadEnd   = 0x22;
        public const byte UploadAck   = 0x23;

        public const byte DownloadReq  = 0x30;
        public const byte DownloadData = 0x31;
        public const byte DownloadEnd  = 0x32;

        public const byte Error      = 0xF0;
        public const byte KeepAlive  = 0xF1;
    }
}