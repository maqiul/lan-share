using System;

namespace LanShareMount.Util
{
    /// <summary>Path normalization helpers — Dokan gives us "\" paths, server uses "/".</summary>
    public static class PathUtil
    {
        /// <summary>
        /// Convert a Dokan-style wide path like "\foo\bar" to a UTF-8 forward-slash
        /// path like "/foo/bar" suitable for sending to the WSP server.
        /// </summary>
        public static string DokanToUtf8(string wp)
        {
            if (string.IsNullOrEmpty(wp)) return "/";
            // Trim trailing backslash for files (but keep root "/")
            string s = wp.Replace('\\', '/');
            while (s.Length > 1 && s[s.Length - 1] == '/')
                s = s.Substring(0, s.Length - 1);
            return s;
        }

        public static DateTime FromUnixTime(long unixSeconds)
        {
            try
            {
                return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                    .AddSeconds(unixSeconds);
            }
            catch { return DateTime.MinValue; }
        }

        public static long ToUnixTime(DateTime dt)
        {
            return (long)(dt.ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
        }
    }
}