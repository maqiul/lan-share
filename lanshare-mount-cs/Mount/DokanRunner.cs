using System;
using System.Runtime.InteropServices;
using LanShareMount.Network;
using LanShareMount.Util;

namespace LanShareMount.Mount
{
    /// <summary>Mount entry point: parses options, builds DOKAN_OPERATIONS, runs DokanMain.</summary>
    public static class DokanRunner
    {
        public static int Unmount(char driveLetter)
        {
            if (DokanNative.DokanUnmount(driveLetter))
            {
                Console.WriteLine("Drive {0}: unmounted.", driveLetter);
                return 0;
            }
            Console.Error.WriteLine("Failed to unmount {0}:", driveLetter);
            return 1;
        }

        public static int RunMount(MountOptions opts)
        {
            // Verify Dokan driver is installed (XP needs 0.6.0, others can be newer)
            ulong ver = DokanNative.DokanVersion();
            Console.WriteLine("Dokan version: {0} ({1}.{2}.{3})",
                ver, (ver >> 24) & 0xFF, (ver >> 16) & 0xFF, ver & 0xFFFF);
            if (ver == 0)
            {
                Console.Error.WriteLine("Dokan driver not installed. Run DokanInstall_0.6.0.exe first.");
                return 1;
            }
            // Tell user if it's an unsupported version
            // Dokan 0.6.0 returns 0x00000600, 0.7.4 returns 0x00000704, 1.x returns 0xA00/0xB00 etc.
            if (ver != 0 && ver < 600UL)
            {
                Console.Error.WriteLine("Dokan version too old ({0}). Need >= 0.6.0 (encoded as 600).", ver);
                return 1;
            }

            var wsp = new WspClient(opts.Host, opts.Port, opts.Pin ?? opts.Pass);
            try
            {
                Console.WriteLine("Connecting to {0}:{1} ...", opts.Host, opts.Port);
                wsp.Connect();
                Console.WriteLine("Authenticated as: {0}", wsp.Username ?? "(unknown)");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Connection failed: {0}", ex.Message);
                wsp.Dispose();
                return 1;
            }

            // Map "L:" → "L:\"
            string mountPoint = char.ToUpperInvariant(opts.Drive[0]) + ":\\";

            var fs = new LanShareFs(wsp);
            var ops = fs.BuildOps();

            var options = new DokanNative.DOKAN_OPTIONS
            {
                Version = DokanNative.DOKAN_VERSION,
                ThreadCount = 4,
                Options = DokanNative.DOKAN_OPTION_KEEP_ALIVE
                       | DokanNative.DOKAN_OPTION_DEBUG
                       | (opts.Debug ? DokanNative.DOKAN_OPTION_STDERR : 0),
                MountPoint = mountPoint,
            };

            Console.WriteLine("Mounting on {0} ...", mountPoint);
            int status;
            try
            {
                status = DokanNative.DokanMain(ref options, ref ops);
            }
            catch (DllNotFoundException)
            {
                Console.Error.WriteLine("dokan.dll not found in PATH or current directory.");
                Console.Error.WriteLine("Run DokanInstall_0.6.0.exe to install the driver.");
                wsp.Dispose();
                return 1;
            }

            wsp.Dispose();

            if (status == 0 || status == -4) return 0;
            Console.Error.WriteLine("Mount failed with status {0}", status);
            return 1;
        }
    }
}