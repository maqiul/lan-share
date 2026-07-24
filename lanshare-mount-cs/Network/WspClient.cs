using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using LanShareMount.Util;

namespace LanShareMount.Network
{
    /// <summary>
    /// WSP client. Holds a single locked connection to the LanShare server,
    /// auto-reconnects on broken pipes, exposes file-system primitives
    /// the Dokan filesystem expects.
    /// </summary>
    public sealed class WspClient : IDisposable
    {
        readonly string _host;
        readonly int _port;
        readonly string _token; // PIN or session token
        readonly object _lock = new object();
        WebSocket _ws;
        uint _nextSeq;
        string _username;
        bool _disposed;

        // Tiny cache (path → exists/is_dir/size/mtime)
        readonly Dictionary<string, FileStat> _cache = new Dictionary<string, FileStat>(
            StringComparer.Ordinal);
        readonly object _cacheLock = new object();
        DateTime _cacheExpiry = DateTime.MinValue;
        const int CacheTtlSeconds = 2;

        public string Username { get { lock (_lock) return _username; } }

        public WspClient(string host, int port, string token)
        {
            _host = host;
            _port = port;
            _token = token;
        }

        public void Connect()
        {
            lock (_lock)
            {
                if (_disposed) throw new ObjectDisposedException("WspClient");
                if (_ws != null) return;

                var ws = new WebSocket(_host, _port, "/wsp");
                ws.Connect();

                // Expect server Hello first
                var hello = WspFrame.Decode(ws.Receive());
                if (hello.MsgType != MsgType.Hello)
                    throw new IOException("Expected Hello, got " + hello.MsgType);

                // Send Auth
                var auth = new WspFrame(MsgType.Auth, 0, NextSeq(),
                    WspFrame.WriteJson("{\"token\":\"" + JsonEscape(_token) + "\"}"));
                ws.SendBinary(auth.Encode());

                // Expect AuthAck
                var ack = WspFrame.Decode(ws.Receive());
                if (ack.MsgType != MsgType.AuthAck)
                    throw new IOException("Expected AuthAck, got " + ack.MsgType);

                // Parse ack JSON manually (no JSON.NET on net40 by default)
                var json = ack.PayloadAsString();
                if (json.IndexOf("\"ok\":true") < 0 && !json.Contains("\"ok\": true"))
                    throw new IOException("Authentication failed: " + json);

                int userIdx = json.IndexOf("\"user\":\"");
                if (userIdx >= 0)
                {
                    int start = userIdx + 8;
                    int end = json.IndexOf('"', start);
                    if (end > start) _username = json.Substring(start, end - start);
                }

                _ws = ws;
                InvalidateCache();
            }
        }

        public void Disconnect()
        {
            lock (_lock)
            {
                if (_ws != null)
                {
                    try { _ws.Close(); } catch { }
                    _ws = null;
                }
            }
        }

        public void Dispose()
        {
            _disposed = true;
            Disconnect();
        }

        // ─── Public filesystem primitives ────────────────────────────────

        public FileStat Stat(string path)
        {
            // Cache check
            FileStat cached;
            lock (_cacheLock)
            {
                if (_cache.TryGetValue(path, out cached) && DateTime.UtcNow < _cacheExpiry)
                    return cached;
            }

            var resp = Request(MsgType.Stat, MsgType.StatResp, "{\"path\":\"" + JsonEscape(path) + "\"}");
            if (resp.MsgType == MsgType.Error)
                return null;
            var s = ParseStat(resp.PayloadAsString());
            lock (_cacheLock) _cache[path] = s;
            return s;
        }

        public List<DirEntry> ListDir(string path)
        {
            var resp = Request(MsgType.ListDir, MsgType.ListDirResp,
                "{\"path\":\"" + JsonEscape(path) + "\"}");
            if (resp.MsgType == MsgType.Error)
                return new List<DirEntry>();

            var json = resp.PayloadAsString();
            var entries = new List<DirEntry>();
            int i = json.IndexOf("\"entries\":[");
            if (i < 0) return entries;
            int start = json.IndexOf('[', i);
            int depth = 0;
            int pos = start + 1;
            while (pos < json.Length)
            {
                char c = json[pos];
                if (c == '{') depth++;
                else if (c == '}') depth--;
                else if (c == ']' && depth == 0) break;
                if (c == '{' && depth == 1)
                {
                    int end = json.IndexOf('}', pos);
                    if (end < 0) break;
                    string obj = json.Substring(pos, end - pos + 1);
                    entries.Add(ParseDirEntry(obj));
                    pos = end + 1;
                    continue;
                }
                pos++;
            }
            return entries;
        }

        public bool Mkdir(string path)
        {
            var resp = Request(MsgType.Mkdir, MsgType.OpAck, "{\"path\":\"" + JsonEscape(path) + "\"}");
            InvalidateCache();
            return resp.MsgType == MsgType.OpAck && resp.PayloadAsString().Contains("\"ok\":true");
        }

        public bool Delete(string path)
        {
            var resp = Request(MsgType.Delete, MsgType.OpAck, "{\"path\":\"" + JsonEscape(path) + "\"}");
            InvalidateCache();
            return resp.MsgType == MsgType.OpAck && resp.PayloadAsString().Contains("\"ok\":true");
        }

        public bool Rename(string oldPath, string newPath)
        {
            var resp = Request(MsgType.Rename, MsgType.OpAck,
                "{\"old_path\":\"" + JsonEscape(oldPath) + "\",\"new_path\":\"" + JsonEscape(newPath) + "\"}");
            InvalidateCache();
            return resp.MsgType == MsgType.OpAck && resp.PayloadAsString().Contains("\"ok\":true");
        }

        public byte[] ReadAll(string path)
        {
            return RequestDownload(path, 0);
        }

        /// <summary>Read bytes starting at <paramref name="offset"/>. Returns up to <paramref name="count"/> bytes.</summary>
        public int ReadAt(string path, long offset, int count)
        {
            var resp = RequestDownload(path, offset);
            if (resp == null) return 0;
            return Math.Min(count, resp.Length);
        }

        public bool Write(string path, byte[] data, long offset)
        {
            uint sid = NewStreamId();
            // UPLOAD_START
            var start = new WspFrame(MsgType.UploadStart, sid, NextSeq(),
                WspFrame.WriteJson("{\"path\":\"" + JsonEscape(path) + "\",\"size\":" + data.Length + "}"));
            SendFrame(start);

            // UPLOAD_DATA: payload = offset(8) + data
            var payload = new byte[8 + data.Length];
            for (int i = 0; i < 8; i++) payload[i] = (byte)((offset >> ((7 - i) * 8)) & 0xFF);
            Buffer.BlockCopy(data, 0, payload, 8, data.Length);
            var dat = new WspFrame(MsgType.UploadData, sid, NextSeq(), payload);
            SendFrame(dat);

            // UPLOAD_END
            var end = new WspFrame(MsgType.UploadEnd, sid, NextSeq(),
                WspFrame.WriteJson("{\"path\":\"" + JsonEscape(path) + "\",\"size\":" + data.Length + "}"));
            SendFrame(end);

            var ack = ReceiveFrame();
            if (ack.MsgType == MsgType.Error) return false;
            if (ack.MsgType != MsgType.UploadAck && ack.MsgType != MsgType.OpAck) return false;
            InvalidateCache();
            return true;
        }

        // ─── Internal helpers ────────────────────────────────────────────

        uint NextSeq() { lock (_lock) { return ++_nextSeq; } }
        uint NewStreamId() { lock (_lock) { return (++_nextSeq) | 0x80000000; } }

        void InvalidateCache()
        {
            lock (_cacheLock)
            {
                _cache.Clear();
                _cacheExpiry = DateTime.UtcNow.AddSeconds(CacheTtlSeconds);
            }
        }

        WspFrame Request(byte reqType, byte respType, string jsonBody)
        {
            uint sid = NewStreamId();
            var req = new WspFrame(reqType, sid, NextSeq(), WspFrame.WriteJson(jsonBody));
            SendFrame(req);
            var resp = ReceiveFrame();
            if (resp.MsgType == MsgType.Error)
            {
                int codeIdx = resp.PayloadAsString().IndexOf("\"message\":\"");
                string msg = "";
                if (codeIdx >= 0)
                {
                    int s = codeIdx + 11;
                    int e = resp.PayloadAsString().IndexOf('"', s);
                    if (e > s) msg = resp.PayloadAsString().Substring(s, e - s);
                }
                throw new IOException("WSP error: " + msg);
            }
            return resp;
        }

        byte[] RequestDownload(string path, long offset)
        {
            uint sid = NewStreamId();
            var req = new WspFrame(MsgType.DownloadReq, sid, NextSeq(),
                WspFrame.WriteJson("{\"path\":\"" + JsonEscape(path) + "\",\"offset\":" + offset + "}"));
            SendFrame(req);

            // Stream DOWNLOAD_DATA frames until DOWNLOAD_END or ERROR
            var ms = new System.IO.MemoryStream();
            while (true)
            {
                var resp = ReceiveFrame();
                if (resp.MsgType == MsgType.Error)
                {
                    int codeIdx = resp.PayloadAsString().IndexOf("\"message\":\"");
                    string msg = "download error";
                    if (codeIdx >= 0)
                    {
                        int s = codeIdx + 11;
                        int e = resp.PayloadAsString().IndexOf('"', s);
                        if (e > s) msg = resp.PayloadAsString().Substring(s, e - s);
                    }
                    throw new IOException("WSP " + msg);
                }
                if (resp.MsgType == MsgType.DownloadEnd) break;
                if (resp.MsgType != MsgType.DownloadData) continue;

                // Skip 8-byte offset + 1-byte is_last flag
                int payloadOff = 9;
                int payloadLen = resp.Payload.Length - payloadOff;
                if (payloadLen > 0)
                    ms.Write(resp.Payload, payloadOff, payloadLen);
            }
            return ms.ToArray();
        }

        void SendFrame(WspFrame frame)
        {
            lock (_lock)
            {
                if (_ws == null) throw new IOException("WSP not connected");
                _ws.SendBinary(frame.Encode());
            }
        }

        WspFrame ReceiveFrame()
        {
            lock (_lock)
            {
                if (_ws == null) throw new IOException("WSP not connected");
                byte[] raw;
                try
                {
                    raw = _ws.Receive();
                }
                catch (Exception)
                {
                    // Connection broke — try once after reconnect
                    Disconnect();
                    Connect();
                    raw = _ws.Receive();
                }
                if (raw == null) throw new IOException("WSP connection closed");
                return WspFrame.Decode(raw);
            }
        }

        static FileStat ParseStat(string json)
        {
            var s = new FileStat { Exists = false };
            int existsIdx = json.IndexOf("\"exists\":");
            if (existsIdx >= 0)
            {
                string tail = json.Substring(existsIdx + 9).TrimStart();
                s.Exists = tail.StartsWith("true");
            }
            if (!s.Exists) return s;

            int nameIdx = json.IndexOf("\"name\":\"");
            if (nameIdx >= 0)
            {
                int start = nameIdx + 8;
                int end = json.IndexOf('"', start);
                s.Name = json.Substring(start, end - start);
            }
            int isDirIdx = json.IndexOf("\"is_dir\":");
            if (isDirIdx >= 0)
            {
                string tail = json.Substring(isDirIdx + 8).TrimStart();
                s.IsDir = tail.StartsWith("true");
            }
            int sizeIdx = json.IndexOf("\"size\":");
            if (sizeIdx >= 0)
            {
                int start = sizeIdx + 7;
                int end = json.IndexOfAny(new[] { ',', '}' }, start);
                long sz;
                if (long.TryParse(json.Substring(start, end - start), out sz))
                    s.Size = (ulong)sz;
            }
            int mtimeIdx = json.IndexOf("\"mtime\":");
            if (mtimeIdx >= 0)
            {
                // mtime is a string ISO-ish; skip detailed parsing, use as opaque
                s.MTime = 0;
            }
            return s;
        }

        static DirEntry ParseDirEntry(string json)
        {
            var e = new DirEntry { Name = "" };
            int nameIdx = json.IndexOf("\"name\":\"");
            if (nameIdx >= 0)
            {
                int start = nameIdx + 8;
                int end = json.IndexOf('"', start);
                e.Name = json.Substring(start, end - start);
            }
            int isDirIdx = json.IndexOf("\"is_dir\":");
            if (isDirIdx >= 0)
            {
                string tail = json.Substring(isDirIdx + 8).TrimStart();
                e.IsDir = tail.StartsWith("true");
            }
            int sizeIdx = json.IndexOf("\"size\":");
            if (sizeIdx >= 0)
            {
                int start = sizeIdx + 7;
                int end = json.IndexOfAny(new[] { ',', '}' }, start);
                long sz;
                if (long.TryParse(json.Substring(start, end - start), out sz))
                    e.Size = (ulong)sz;
            }
            return e;
        }

        static string JsonEscape(string s)
        {
            if (s == null) return "";
            var sb = new StringBuilder(s.Length + 8);
            foreach (char c in s)
            {
                switch (c)
                {
                    case '\\': sb.Append("\\\\"); break;
                    case '"':  sb.Append("\\\""); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.AppendFormat("\\u{0:x4}", (int)c);
                        else sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }
    }

    public sealed class FileStat
    {
        public bool Exists;
        public string Name;
        public bool IsDir;
        public ulong Size;
        public long MTime;
    }

    public sealed class DirEntry
    {
        public string Name;
        public bool IsDir;
        public ulong Size;
    }
}