using System;
using System.Runtime.InteropServices;

namespace LanShareMount.Mount
{
    /// <summary>
    /// P/Invoke bindings for dokan.dll 0.6.0 (last XP-compatible release).
    /// Mirrors dokan.h's DOKAN_OPERATIONS vtable and DokanMain entry point.
    /// </summary>
    public static class DokanNative
    {
        public const ushort DOKAN_VERSION = 740;

        // DOKAN_OPTIONS.Flags
        public const uint DOKAN_OPTION_DEBUG        = 1;
        public const uint DOKAN_OPTION_STDERR       = 2;
        public const uint DOKAN_OPTION_ALT_STREAM   = 4;
        public const uint DOKAN_OPTION_KEEP_ALIVE   = 8;
        public const uint DOKAN_OPTION_NETWORK      = 16;
        public const uint DOKAN_OPTION_REMOVABLE    = 32;
        public const uint DOKAN_OPTION_MOUNT_MANAGER = 64;
        public const uint DOKAN_OPTION_CURRENT_SESSION = 128;

        // NTSTATUS codes (subset)
        public const int STATUS_SUCCESS              = 0;
        public const int STATUS_OBJECT_NAME_NOT_FOUND = unchecked((int)0xC0000034);
        public const int STATUS_OBJECT_PATH_NOT_FOUND = unchecked((int)0xC000003A);
        public const int STATUS_NOT_A_DIRECTORY       = unchecked((int)0xC0000103);
        public const int STATUS_DIRECTORY_NOT_EMPTY   = unchecked((int)0xC0000101);
        public const int STATUS_ACCESS_DENIED         = unchecked((int)0xC0000022);
        public const int STATUS_SHARING_VIOLATION     = unchecked((int)0xC0000043);
        public const int STATUS_DISK_FULL             = unchecked((int)0xC000007F);
        public const int STATUS_NOT_SUPPORTED         = unchecked((int)0xC00000BB);
        public const int STATUS_INVALID_PARAMETER     = unchecked((int)0xC000000D);
        public const int STATUS_BUFFER_OVERFLOW       = unchecked((int)0xC0000044);

        public const uint FILE_ATTRIBUTE_DIRECTORY  = 0x10;
        public const uint FILE_ATTRIBUTE_NORMAL     = 0x80;

        public const uint GENERIC_READ    = 0x80000000;
        public const uint GENERIC_WRITE   = 0x40000000;
        public const uint FILE_READ_DATA  = 0x0001;
        public const uint FILE_WRITE_DATA = 0x0002;
        public const uint FILE_APPEND_DATA= 0x0004;
        public const uint FILE_SHARE_READ = 0x0001;

        public const int CREATE_NEW        = 1;
        public const int CREATE_ALWAYS     = 2;
        public const int OPEN_EXISTING     = 3;
        public const int OPEN_ALWAYS       = 4;
        public const int TRUNCATE_EXISTING = 5;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DOKAN_OPTIONS
        {
            public ushort Version;
            public ushort ThreadCount;
            public uint Options;
            public ulong GlobalContext;
            [MarshalAs(UnmanagedType.LPWStr)] public string MountPoint;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DOKAN_FILE_INFO
        {
            public ulong Context;
            public ulong DokanContext;
            public IntPtr DokanOptions;
            public uint ProcessId;
            public byte IsDirectory;
            public byte DeleteOnClose;
            public byte PagingIo;
            public byte SynchronousIo;
            public byte Nocache;
            public byte WriteToEndOfFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WIN32_FIND_DATAW
        {
            public uint dwFileAttributes;
            public uint ftCreationTime_dwLowDateTime;
            public uint ftCreationTime_dwHighDateTime;
            public uint ftLastAccessTime_dwLowDateTime;
            public uint ftLastAccessTime_dwHighDateTime;
            public uint ftLastWriteTime_dwLowDateTime;
            public uint ftLastWriteTime_dwHighDateTime;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint dwReserved0;
            public uint dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
            public string cAlternateFileName;
        }

        // Delegates — match DOKAN_OPERATIONS vtable order
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int CreateFileDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName,
            uint desiredAccess, uint shareMode, uint creationDisposition,
            uint flagsAndAttributes, IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int OpenDirectoryDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName, IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int CreateDirectoryDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName, IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int CleanupDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName, IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int CloseFileDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName, IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int ReadFileDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName,
            IntPtr buffer, uint numberOfBytesToRead,
            out uint numberOfBytesRead, long offset, IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int WriteFileDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName,
            IntPtr buffer, uint numberOfBytesToWrite,
            out uint numberOfBytesWritten, long offset, IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int FlushFileBuffersDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName, IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int GetFileInformationDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName,
            IntPtr byHandleFileInformation, IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int FindFilesDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string pathName,
            IntPtr fillFindData, // PFillFindData callback
            IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int FindFilesWithPatternDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string pathName,
            [MarshalAs(UnmanagedType.LPWStr)] string searchPattern,
            IntPtr fillFindData, IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int SetFileAttributesDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName,
            uint fileAttributes, IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int SetFileTimeDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName,
            IntPtr creationTime, IntPtr lastAccessTime, IntPtr lastWriteTime,
            IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int DeleteFileDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName, IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int DeleteDirectoryDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName, IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int MoveFileDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string existingFileName,
            [MarshalAs(UnmanagedType.LPWStr)] string newFileName,
            [MarshalAs(UnmanagedType.Bool)] bool replaceIfExisting,
            IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int SetEndOfFileDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName,
            long length, IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int SetAllocationSizeDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName,
            long length, IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int LockFileDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName,
            long byteOffset, long length, IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int UnlockFileDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName,
            long byteOffset, long length, IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int GetDiskFreeSpaceDelegate(
            out ulong freeBytesAvailable, out ulong totalNumberOfBytes,
            out ulong totalNumberOfFreeBytes, IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int GetVolumeInformationDelegate(
            IntPtr volumeNameBuffer, uint volumeNameSize,
            out uint volumeSerialNumber, out uint maximumComponentLength,
            out uint fileSystemFlags, IntPtr fileSystemNameBuffer,
            uint fileSystemNameSize, IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int UnmountDelegate(IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int GetFileSecurityDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName,
            out uint securityInformation, IntPtr securityDescriptor,
            uint securityDescriptorLength, out uint lengthNeeded,
            IntPtr dokanFileInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int SetFileSecurityDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName,
            out uint securityInformation, IntPtr securityDescriptor,
            uint securityDescriptorLength, IntPtr dokanFileInfo);

        [StructLayout(LayoutKind.Sequential)]
        public struct DOKAN_OPERATIONS
        {
            public IntPtr CreateFile;
            public IntPtr OpenDirectory;
            public IntPtr CreateDirectory;
            public IntPtr Cleanup;
            public IntPtr CloseFile;
            public IntPtr ReadFile;
            public IntPtr WriteFile;
            public IntPtr FlushFileBuffers;
            public IntPtr GetFileInformation;
            public IntPtr FindFiles;
            public IntPtr FindFilesWithPattern;
            public IntPtr SetFileAttributes;
            public IntPtr SetFileTime;
            public IntPtr DeleteFile;
            public IntPtr DeleteDirectory;
            public IntPtr MoveFile;
            public IntPtr SetEndOfFile;
            public IntPtr SetAllocationSize;
            public IntPtr LockFile;
            public IntPtr UnlockFile;
            public IntPtr GetDiskFreeSpace;
            public IntPtr GetVolumeInformation;
            public IntPtr Unmount;
            public IntPtr GetFileSecurity;
            public IntPtr SetFileSecurity;
        }

        [DllImport("dokan.dll", EntryPoint = "DokanMain", CharSet = CharSet.Unicode)]
        public static extern int DokanMain(ref DOKAN_OPTIONS options, ref DOKAN_OPERATIONS operations);

        [DllImport("dokan.dll", EntryPoint = "DokanUnmount")]
        public static extern bool DokanUnmount(char driveLetter);

        [DllImport("dokan.dll", EntryPoint = "DokanRemoveMountPoint", CharSet = CharSet.Unicode)]
        public static extern bool DokanRemoveMountPoint([MarshalAs(UnmanagedType.LPWStr)] string mountPoint);

        [DllImport("dokan.dll", EntryPoint = "DokanVersion")]
        public static extern ulong DokanVersion();

        [DllImport("dokan.dll", EntryPoint = "DokanResetTimeout", CharSet = CharSet.Unicode)]
        public static extern bool DokanResetTimeout(uint timeout, IntPtr dokanFileInfo);

        // PFillFindData callback
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int FillFindDataCallback(IntPtr findData, IntPtr dokanFileInfo);

        // FILETIME helpers
        public static long UnixTimeToFileTime(long unixSeconds)
        {
            // 116444736000000000 = number of 100ns intervals from 1601 to 1970
            return unixSeconds * 10000000L + 116444736000000000L;
        }

        public static void SetFileTime(IntPtr findData, long unixSeconds)
        {
            long ft = UnixTimeToFileTime(unixSeconds);
            uint low = (uint)(ft & 0xFFFFFFFF);
            uint high = (uint)((ft >> 32) & 0xFFFFFFFF);

            // Offset of ftCreationTime in WIN32_FIND_DATAW: 8
            Marshal.WriteInt32(findData, 8,  (int)low);
            Marshal.WriteInt32(findData, 12, (int)high);
            Marshal.WriteInt32(findData, 16, (int)low);
            Marshal.WriteInt32(findData, 20, (int)high);
            Marshal.WriteInt32(findData, 24, (int)low);
            Marshal.WriteInt32(findData, 28, (int)high);
        }

        public static void MarshalStringToFileName(IntPtr findData, string name)
        {
            // cFileName offset: 56 (32 + 8*3 + 4 + 4 = 56)
            // cFileName size: 520 bytes (260 wide chars)
            // cAlternateFileName offset: 56 + 520 = 576
            int offset = 56;
            byte[] bytes = new byte[520];
            for (int i = 0; i < name.Length && i < 259; i++)
            {
                char c = name[i];
                bytes[i * 2] = (byte)(c & 0xFF);
                bytes[i * 2 + 1] = (byte)((c >> 8) & 0xFF);
            }
            Marshal.Copy(bytes, 0, IntPtr.Add(findData, offset), 520);
        }
    }
}