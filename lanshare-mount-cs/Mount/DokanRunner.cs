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
            if (ver != 0 && ver < 600UL)
            {
                Console.Error.WriteLine("Dokan version too old ({0}). Need >= 0.6.0 (encoded as 600).", ver);
                return 1;
            }

            char driveLetter = char.ToUpperInvariant(opts.Drive[0]);

            // Single-instance guard: refuse to start if another copy is already
            // mounted on this drive letter. Uses a PID file in %TEMP% so a
            // crashed process doesn't permanently block the drive.
            int myPid = System.Diagnostics.Process.GetCurrentProcess().Id;
            string lockPath = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "lanshare-mount-" + driveLetter + ".lock");
            if (System.IO.File.Exists(lockPath))
            {
                int existingPid = 0;
                try { existingPid = int.Parse(System.IO.File.ReadAllText(lockPath).Trim()); } catch { }
                if (existingPid > 0)
                {
                    bool alive = false;
                    try
                    {
                        var p = System.Diagnostics.Process.GetProcessById(existingPid);
                        alive = !p.HasExited;
                        // Sanity: make sure it's actually our process
                        alive = alive && System.IO.File.Exists(
                            System.IO.Path.Combine(System.IO.Path.GetTempPath(), "lanshare-mount-" + existingPid + ".alive"));
                    }
                    catch { alive = false; }
                    if (alive)
                    {
                        Console.Error.WriteLine(
                            "Another Lanshare mount instance is already running on {0}: (PID {1}).",
                            driveLetter, existingPid);
                        Console.Error.WriteLine("Use that one, or kill it first.");
                        return 1;
                    }
                    Console.WriteLine("Removing stale lock file from previous run (PID {0}).", existingPid);
                    try { System.IO.File.Delete(lockPath); } catch { }
                }
            }
            System.IO.File.WriteAllText(lockPath, myPid.ToString());
            string heartbeatPath = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(), "lanshare-mount-" + myPid + ".alive");
            System.IO.File.WriteAllText(heartbeatPath, "1");

            try
            {
                // If a previous mapping is still around on the same drive letter,
                // try to unmount it first so DokanMain doesn't fail with -5.
                string mountPoint = driveLetter + ":\\";
                bool removed = DokanNative.DokanRemoveMountPoint(mountPoint);
                if (removed)
                {
                    Console.WriteLine("Removed stale mount on {0}:", driveLetter);
                    System.Threading.Thread.Sleep(500);
                }

                return RunMountInner(opts, driveLetter, mountPoint);
            }
            finally
            {
                // Always clean up lock + heartbeat so a future process can start
                try { System.IO.File.Delete(lockPath); } catch { }
                try { System.IO.File.Delete(heartbeatPath); } catch { }
            }
        }

        static int RunMountInner(MountOptions opts, char driveLetter, string mountPoint)
        {

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
            if (status == -5)
            {
                Console.Error.WriteLine(
                    "Mount failed: drive {0}: is already in use by another application " +
                    "or a stale Dokan mount. Try a different drive letter.", driveLetter);
                return 1;
            }
            Console.Error.WriteLine("Mount failed with status {0}", status);
            return 1;
        }
    }
}