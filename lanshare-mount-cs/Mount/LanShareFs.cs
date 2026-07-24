using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using LanShareMount.Network;
using LanShareMount.Util;

namespace LanShareMount.Mount
{
    /// <summary>
    /// Dokan file-system callbacks backed by a WSP connection to LanShare server.
    /// All callbacks are __stdcall and must be very fast — heavy work goes through
    /// the WspClient, which may reconnect on transient failures.
    /// </summary>
    public sealed class LanShareFs
    {
        readonly WspClient _wsp;
        readonly Dictionary<string, PendingWrite> _pendingWrites =
            new Dictionary<string, PendingWrite>(StringComparer.Ordinal);
        readonly object _pendingLock = new object();
        readonly Dictionary<DokanNative.FillFindDataCallback, object> _pinFillCallback =
            new Dictionary<DokanNative.FillFindDataCallback, object>();

        public LanShareFs(WspClient wsp) { _wsp = wsp; }

        sealed class PendingWrite
        {
            public MemoryStream Stream;
            public long ExpectedSize = -1;
        }

        internal DokanNative.DOKAN_OPERATIONS BuildOps()
        {
            var ops = new DokanNative.DOKAN_OPERATIONS();
            ops.CreateFile = Marshal.GetFunctionPointerForDelegate(
                (DokanNative.CreateFileDelegate)OnCreateFile);
            ops.OpenDirectory = Marshal.GetFunctionPointerForDelegate(
                (DokanNative.OpenDirectoryDelegate)OnOpenDirectory);
            ops.CreateDirectory = Marshal.GetFunctionPointerForDelegate(
                (DokanNative.CreateDirectoryDelegate)OnCreateDirectory);
            ops.Cleanup = Marshal.GetFunctionPointerForDelegate(
                (DokanNative.CleanupDelegate)OnCleanup);
            ops.CloseFile = Marshal.GetFunctionPointerForDelegate(
                (DokanNative.CloseFileDelegate)OnCloseFile);
            ops.ReadFile = Marshal.GetFunctionPointerForDelegate(
                (DokanNative.ReadFileDelegate)OnReadFile);
            ops.WriteFile = Marshal.GetFunctionPointerForDelegate(
                (DokanNative.WriteFileDelegate)OnWriteFile);
            ops.FlushFileBuffers = Marshal.GetFunctionPointerForDelegate(
                (DokanNative.FlushFileBuffersDelegate)OnFlushFileBuffers);
            ops.GetFileInformation = Marshal.GetFunctionPointerForDelegate(
                (DokanNative.GetFileInformationDelegate)OnGetFileInformation);
            ops.FindFiles = Marshal.GetFunctionPointerForDelegate(
                (DokanNative.FindFilesDelegate)OnFindFiles);
            ops.FindFilesWithPattern = IntPtr.Zero;
            ops.SetFileAttributes = IntPtr.Zero;
            ops.SetFileTime = IntPtr.Zero;
            ops.DeleteFile = Marshal.GetFunctionPointerForDelegate(
                (DokanNative.DeleteFileDelegate)OnDeleteFile);
            ops.DeleteDirectory = Marshal.GetFunctionPointerForDelegate(
                (DokanNative.DeleteDirectoryDelegate)OnDeleteDirectory);
            ops.MoveFile = Marshal.GetFunctionPointerForDelegate(
                (DokanNative.MoveFileDelegate)OnMoveFile);
            ops.SetEndOfFile = Marshal.GetFunctionPointerForDelegate(
                (DokanNative.SetEndOfFileDelegate)OnSetEndOfFile);
            ops.SetAllocationSize = IntPtr.Zero;
            ops.LockFile = IntPtr.Zero;
            ops.UnlockFile = IntPtr.Zero;
            ops.GetDiskFreeSpace = Marshal.GetFunctionPointerForDelegate(
                (DokanNative.GetDiskFreeSpaceDelegate)OnGetDiskFreeSpace);
            ops.GetVolumeInformation = Marshal.GetFunctionPointerForDelegate(
                (DokanNative.GetVolumeInformationDelegate)OnGetVolumeInformation);
            ops.Unmount = Marshal.GetFunctionPointerForDelegate(
                (DokanNative.UnmountDelegate)OnUnmount);
            ops.GetFileSecurity = IntPtr.Zero;
            ops.SetFileSecurity = IntPtr.Zero;
            return ops;
        }

        static DokanNative.DOKAN_FILE_INFO GetInfo(IntPtr p)
        {
            return (DokanNative.DOKAN_FILE_INFO)Marshal.PtrToStructure(p, typeof(DokanNative.DOKAN_FILE_INFO));
        }

        static void SetDirectoryFlag(IntPtr info, bool isDir)
        {
            var fi = GetInfo(info);
            fi.IsDirectory = (byte)(isDir ? 1 : 0);
            Marshal.StructureToPtr(fi, info, false);
        }

        int OnCreateFile(string fileName, uint desiredAccess, uint shareMode,
            uint creationDisposition, uint flagsAndAttributes, IntPtr dokanFileInfo)
        {
            try
            {
                var path = PathUtil.DokanToUtf8(fileName);
                var stat = _wsp.Stat(path);
                if (stat == null || !stat.Exists)
                {
                    if (creationDisposition == DokanNative.CREATE_NEW ||
                        creationDisposition == DokanNative.CREATE_ALWAYS ||
                        creationDisposition == DokanNative.OPEN_ALWAYS)
                    {
                        // File doesn't exist but caller wants to create — let it through
                        // (next WriteFile will create on server)
                        return DokanNative.STATUS_SUCCESS;
                    }
                    return DokanNative.STATUS_OBJECT_NAME_NOT_FOUND;
                }
                SetDirectoryFlag(dokanFileInfo, stat.IsDir);
                return DokanNative.STATUS_SUCCESS;
            }
            catch (Exception)
            {
                return DokanNative.STATUS_INVALID_PARAMETER;
            }
        }

        int OnOpenDirectory(string fileName, IntPtr dokanFileInfo)
        {
            try
            {
                var path = PathUtil.DokanToUtf8(fileName);
                var stat = _wsp.Stat(path);
                if (stat == null || !stat.Exists) return DokanNative.STATUS_OBJECT_PATH_NOT_FOUND;
                if (!stat.IsDir) return DokanNative.STATUS_NOT_A_DIRECTORY;
                SetDirectoryFlag(dokanFileInfo, true);
                return DokanNative.STATUS_SUCCESS;
            }
            catch { return DokanNative.STATUS_INVALID_PARAMETER; }
        }

        int OnCreateDirectory(string fileName, IntPtr dokanFileInfo)
        {
            try
            {
                return _wsp.Mkdir(PathUtil.DokanToUtf8(fileName))
                    ? DokanNative.STATUS_SUCCESS
                    : DokanNative.STATUS_ACCESS_DENIED;
            }
            catch { return DokanNative.STATUS_INVALID_PARAMETER; }
        }

        int OnCleanup(string fileName, IntPtr dokanFileInfo)
        {
            // When Dokan is done with the file, write pending data to the server.
            string path;
            try { path = PathUtil.DokanToUtf8(fileName); }
            catch { return DokanNative.STATUS_SUCCESS; }

            PendingWrite pending = null;
            lock (_pendingLock)
            {
                if (_pendingWrites.TryGetValue(path, out pending))
                    _pendingWrites.Remove(path);
            }
            if (pending == null || pending.Stream == null) return DokanNative.STATUS_SUCCESS;
            try
            {
                byte[] data = pending.Stream.ToArray();
                pending.Stream.Dispose();
                if (!_wsp.Write(path, data, 0))
                    return DokanNative.STATUS_ACCESS_DENIED;
                return DokanNative.STATUS_SUCCESS;
            }
            catch { return DokanNative.STATUS_INVALID_PARAMETER; }
        }

        int OnCloseFile(string fileName, IntPtr dokanFileInfo) { return DokanNative.STATUS_SUCCESS; }
        int OnFlushFileBuffers(string fileName, IntPtr dokanFileInfo) { return DokanNative.STATUS_SUCCESS; }

        int OnReadFile(string fileName, IntPtr buffer, uint numberOfBytesToRead,
            out uint numberOfBytesRead, long offset, IntPtr dokanFileInfo)
        {
            numberOfBytesRead = 0;
            try
            {
                var path = PathUtil.DokanToUtf8(fileName);
                // Simple: download full file (WSP server streams, so this is OK)
                var data = _wsp.ReadAll(path);
                if (data == null) return DokanNative.STATUS_INVALID_PARAMETER;
                if (offset >= data.Length) return DokanNative.STATUS_SUCCESS;
                long available = data.Length - offset;
                int toCopy = (int)Math.Min((long)numberOfBytesToRead, available);
                if (toCopy > 0)
                    Marshal.Copy(data, (int)offset, buffer, toCopy);
                numberOfBytesRead = (uint)toCopy;
                return DokanNative.STATUS_SUCCESS;
            }
            catch { return DokanNative.STATUS_INVALID_PARAMETER; }
        }

        int OnWriteFile(string fileName, IntPtr buffer, uint numberOfBytesToWrite,
            out uint numberOfBytesWritten, long offset, IntPtr dokanFileInfo)
        {
            numberOfBytesWritten = 0;
            try
            {
                var path = PathUtil.DokanToUtf8(fileName);
                byte[] data = new byte[numberOfBytesToWrite];
                if (numberOfBytesToWrite > 0)
                    Marshal.Copy(buffer, data, 0, (int)numberOfBytesToWrite);

                lock (_pendingLock)
                {
                    PendingWrite pending;
                    if (!_pendingWrites.TryGetValue(path, out pending))
                    {
                        pending = new PendingWrite { Stream = new MemoryStream() };
                        _pendingWrites[path] = pending;
                    }
                    if (pending.Stream.Length < offset)
                    {
                        // Extend stream with zeros
                        var pad = new byte[offset - pending.Stream.Length];
                        pending.Stream.Write(pad, 0, pad.Length);
                    }
                    else if (pending.Stream.Length > offset && offset > 0)
                    {
                        // Overwrite at offset — MemoryStream doesn't support seek-write easily,
                        // so rebuild
                        long newLen = Math.Max(pending.Stream.Length, offset + data.Length);
                        var all = pending.Stream.ToArray();
                        if (all.Length < newLen)
                        {
                            var grown = new byte[newLen];
                            Buffer.BlockCopy(all, 0, grown, 0, all.Length);
                            all = grown;
                        }
                        pending.Stream.Dispose();
                        var ms = new MemoryStream(all);
                        pending.Stream = ms;
                    }
                    pending.Stream.Position = offset;
                    pending.Stream.Write(data, 0, data.Length);
                }

                numberOfBytesWritten = numberOfBytesToWrite;
                return DokanNative.STATUS_SUCCESS;
            }
            catch { return DokanNative.STATUS_INVALID_PARAMETER; }
        }

        int OnGetFileInformation(string fileName, IntPtr byHandleFileInformation, IntPtr dokanFileInfo)
        {
            try
            {
                var stat = _wsp.Stat(PathUtil.DokanToUtf8(fileName));
                if (stat == null || !stat.Exists) return DokanNative.STATUS_OBJECT_NAME_NOT_FOUND;

                // BY_HANDLE_FILE_INFORMATION layout (20 uints):
                // 0: dwFileAttributes
                // 4: ftCreationTime.dwLowDateTime, 8: ftCreationTime.dwHighDateTime
                // 12: ftLastAccessTime.low, 16: ftLastAccessTime.high
                // 20: ftLastWriteTime.low, 24: ftLastWriteTime.high
                // 28: dwVolumeSerialNumber
                // 32: nFileSizeHigh, 36: nFileSizeLow
                // 40: nNumberOfLinks
                // 44: nFileIndex (low), 48: nFileIndex (high)
                // 52: dwReserved0..3 (16 bytes)

                Marshal.WriteInt32(byHandleFileInformation, 0,
                    (int)(stat.IsDir ? DokanNative.FILE_ATTRIBUTE_DIRECTORY : DokanNative.FILE_ATTRIBUTE_NORMAL));

                long ft = DokanNative.UnixTimeToFileTime(stat.MTime);
                uint low = (uint)(ft & 0xFFFFFFFF);
                uint high = (uint)((ft >> 32) & 0xFFFFFFFF);

                Marshal.WriteInt32(byHandleFileInformation, 4,  (int)low);
                Marshal.WriteInt32(byHandleFileInformation, 8,  (int)high);
                Marshal.WriteInt32(byHandleFileInformation, 12, (int)low);
                Marshal.WriteInt32(byHandleFileInformation, 16, (int)high);
                Marshal.WriteInt32(byHandleFileInformation, 20, (int)low);
                Marshal.WriteInt32(byHandleFileInformation, 24, (int)high);

                Marshal.WriteInt32(byHandleFileInformation, 32, (int)(stat.Size >> 32));
                Marshal.WriteInt32(byHandleFileInformation, 36, (int)(stat.Size & 0xFFFFFFFF));
                return DokanNative.STATUS_SUCCESS;
            }
            catch { return DokanNative.STATUS_INVALID_PARAMETER; }
        }

        // The FillFindData callback is given to us as a function pointer per OnFindFiles call.
        // Dokan calls FillFindData with a pointer to a WIN32_FIND_DATAW it allocated, and expects us
        // to fill it in and return 0 (or non-zero to stop enumeration).
        int OnFindFiles(string pathName, IntPtr fillFindData, IntPtr dokanFileInfo)
        {
            try
            {
                var path = PathUtil.DokanToUtf8(pathName);
                var entries = _wsp.ListDir(path);
                if (entries == null) return DokanNative.STATUS_SUCCESS;

                // Marshal the function pointer to a delegate
                var fillCb = (DokanNative.FillFindDataCallback)
                    Marshal.GetDelegateForFunctionPointer(fillFindData,
                        typeof(DokanNative.FillFindDataCallback));

                foreach (var e in entries)
                {
                    var fdata = new DokanNative.WIN32_FIND_DATAW();
                    fdata.dwFileAttributes = (uint)(e.IsDir
                        ? DokanNative.FILE_ATTRIBUTE_DIRECTORY
                        : DokanNative.FILE_ATTRIBUTE_NORMAL);
                    long ft = DokanNative.UnixTimeToFileTime(0);
                    fdata.ftCreationTime_dwLowDateTime    = (uint)(ft & 0xFFFFFFFF);
                    fdata.ftCreationTime_dwHighDateTime   = (uint)((ft >> 32) & 0xFFFFFFFF);
                    fdata.ftLastAccessTime_dwLowDateTime  = fdata.ftCreationTime_dwLowDateTime;
                    fdata.ftLastAccessTime_dwHighDateTime = fdata.ftCreationTime_dwHighDateTime;
                    fdata.ftLastWriteTime_dwLowDateTime   = fdata.ftCreationTime_dwLowDateTime;
                    fdata.ftLastWriteTime_dwHighDateTime  = fdata.ftCreationTime_dwHighDateTime;
                    fdata.nFileSizeHigh = (uint)(e.Size >> 32);
                    fdata.nFileSizeLow  = (uint)(e.Size & 0xFFFFFFFF);
                    fdata.cFileName = e.Name;
                    fdata.cAlternateFileName = "";

                    IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf(fdata));
                    try
                    {
                        Marshal.StructureToPtr(fdata, p, false);
                        if (fillCb(p, dokanFileInfo) != 0) break;
                    }
                    finally { Marshal.FreeHGlobal(p); }
                }
                return DokanNative.STATUS_SUCCESS;
            }
            catch { return DokanNative.STATUS_INVALID_PARAMETER; }
        }

        int OnDeleteFile(string fileName, IntPtr dokanFileInfo)
        {
            try
            {
                return _wsp.Delete(PathUtil.DokanToUtf8(fileName))
                    ? DokanNative.STATUS_SUCCESS
                    : DokanNative.STATUS_ACCESS_DENIED;
            }
            catch { return DokanNative.STATUS_INVALID_PARAMETER; }
        }

        int OnDeleteDirectory(string fileName, IntPtr dokanFileInfo)
        {
            try
            {
                return _wsp.Delete(PathUtil.DokanToUtf8(fileName))
                    ? DokanNative.STATUS_SUCCESS
                    : DokanNative.STATUS_DIRECTORY_NOT_EMPTY;
            }
            catch { return DokanNative.STATUS_INVALID_PARAMETER; }
        }

        int OnMoveFile(string existingFileName, string newFileName,
            bool replaceIfExisting, IntPtr dokanFileInfo)
        {
            try
            {
                return _wsp.Rename(PathUtil.DokanToUtf8(existingFileName),
                                   PathUtil.DokanToUtf8(newFileName))
                    ? DokanNative.STATUS_SUCCESS
                    : DokanNative.STATUS_ACCESS_DENIED;
            }
            catch { return DokanNative.STATUS_INVALID_PARAMETER; }
        }

        int OnSetEndOfFile(string fileName, long length, IntPtr dokanFileInfo)
        {
            return DokanNative.STATUS_NOT_SUPPORTED;
        }

        int OnGetDiskFreeSpace(out ulong freeBytesAvailable, out ulong totalNumberOfBytes,
            out ulong totalNumberOfFreeBytes, IntPtr dokanFileInfo)
        {
            // Fake: 1 TB total, 500 GB free
            totalNumberOfBytes = 1024UL * 1024 * 1024 * 1024;
            freeBytesAvailable = 500UL * 1024 * 1024 * 1024;
            totalNumberOfFreeBytes = freeBytesAvailable;
            return DokanNative.STATUS_SUCCESS;
        }

        int OnGetVolumeInformation(IntPtr volumeNameBuffer, uint volumeNameSize,
            out uint volumeSerialNumber, out uint maximumComponentLength,
            out uint fileSystemFlags, IntPtr fileSystemNameBuffer,
            uint fileSystemNameSize, IntPtr dokanFileInfo)
        {
            volumeSerialNumber = 0x4C534848; // 'LSHH'
            maximumComponentLength = 255;
            fileSystemFlags = 0; // simplest

            WriteWChar(volumeNameBuffer, "LanShare", volumeNameSize);
            WriteWChar(fileSystemNameBuffer, "LanShare", fileSystemNameSize);
            return DokanNative.STATUS_SUCCESS;
        }

        static void WriteWChar(IntPtr dst, string s, uint maxChars)
        {
            if (dst == IntPtr.Zero) return;
            uint maxBytes = maxChars * 2;
            byte[] bytes = new byte[maxBytes];
            int charCount = Math.Min(s.Length, (int)maxChars - 1);
            for (int i = 0; i < charCount; i++)
            {
                char c = s[i];
                bytes[i * 2] = (byte)(c & 0xFF);
                bytes[i * 2 + 1] = (byte)((c >> 8) & 0xFF);
            }
            Marshal.Copy(bytes, 0, dst, (int)maxBytes);
        }

        int OnUnmount(IntPtr dokanFileInfo)
        {
            try { _wsp.Disconnect(); } catch { }
            return DokanNative.STATUS_SUCCESS;
        }
    }
}