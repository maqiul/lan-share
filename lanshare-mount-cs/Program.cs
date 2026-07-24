using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using LanShareMount.Network;
using LanShareMount.Mount;
using LanShareMount.Util;

namespace LanShareMount
{
    /// <summary>Parsed command-line options.</summary>
    public sealed class MountOptions
    {
        public string Host;
        public int Port = 8080;
        public string Pin;
        public string User;
        public string Pass;
        public string Drive;
        public bool Unmount;
        public char UnmountDriveLetter;
        public bool Debug;
        public bool ShowVersion;
    }

    internal static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;

            if (args.Length == 0 || args[0] == "--help" || args[0] == "-h")
            {
                PrintUsage();
                return 0;
            }

            try
            {
                var opts = Args.Parse(args);

                if (opts.Unmount)
                {
                    return DokanRunner.Unmount(opts.UnmountDriveLetter);
                }

                if (opts.ShowVersion)
                {
                    var asm = Assembly.GetExecutingAssembly().GetName();
                    Console.WriteLine("LanShare Mount v{0}", asm.Version);
                    Console.WriteLine(".NET Framework {0}", Environment.Version);
                    return 0;
                }

                if (string.IsNullOrEmpty(opts.Host))
                {
                    Console.Error.WriteLine("Error: missing server address. Try --help.");
                    return 1;
                }

                if (string.IsNullOrEmpty(opts.Drive))
                {
                    Console.Error.WriteLine("Error: missing --drive <L:>.");
                    return 1;
                }

                if (string.IsNullOrEmpty(opts.Pin) && (string.IsNullOrEmpty(opts.User) || string.IsNullOrEmpty(opts.Pass)))
                {
                    Console.Error.WriteLine("Error: must specify --pin OR both --user and --pass.");
                    return 1;
                }

                return DokanRunner.RunMount(opts);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Fatal: {0}", ex.Message);
                return 1;
            }
        }

        static void PrintUsage()
        {
            Console.WriteLine("LanShare Mount Client v1.0");
            Console.WriteLine("Mount a LanShare server as a local drive via Dokan.");
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("  lanshare-mount.exe <host:port> --pin <pin> --drive <L:>");
            Console.WriteLine("  lanshare-mount.exe <host:port> --user <u> --pass <p> --drive <L:>");
            Console.WriteLine("  lanshare-mount.exe --unmount <L:>");
            Console.WriteLine("  lanshare-mount.exe --version");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --pin <pin>        Authentication PIN (simple mode)");
            Console.WriteLine("  --user <u> --pass <p>   Account mode authentication");
            Console.WriteLine("  --drive <L:>       Drive letter to mount on (e.g. L:)");
            Console.WriteLine("  --debug            Enable Dokan debug logging to stderr");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  lanshare-mount.exe 192.168.0.100:8080 --pin 123456 --drive L:");
            Console.WriteLine("  lanshare-mount.exe 192.168.0.100:8080 --user alice --pass secret --drive M:");
            Console.WriteLine("  lanshare-mount.exe --unmount L:");
            Console.WriteLine();
            Console.WriteLine("XP requires Dokan 0.6.0 driver installed (download from");
            Console.WriteLine("https://github.com/dokan-dev/dokany/releases/tag/v0.6.0).");
        }
    }

    public static class Args
    {
        public static MountOptions Parse(string[] argv)
        {
            var o = new MountOptions();
            string serverArg = null;

            for (int i = 0; i < argv.Length; i++)
            {
                var a = argv[i];
                switch (a)
                {
                    case "--unmount":
                        if (i + 1 >= argv.Length) throw new ArgumentException("--unmount needs a drive letter");
                        o.Unmount = true;
                        o.UnmountDriveLetter = char.ToUpperInvariant(argv[++i][0]);
                        break;
                    case "--pin":
                        o.Pin = argv[++i];
                        break;
                    case "--user":
                        o.User = argv[++i];
                        break;
                    case "--pass":
                        o.Pass = argv[++i];
                        break;
                    case "--drive":
                        var d = argv[++i];
                        if (string.IsNullOrEmpty(d) || d.Length < 2)
                            throw new ArgumentException("--drive expects a drive letter like L:");
                        o.Drive = d.Substring(0, 2).ToUpperInvariant();
                        break;
                    case "--debug":
                        o.Debug = true;
                        break;
                    case "--version":
                        o.ShowVersion = true;
                        break;
                    default:
                        if (a.StartsWith("--"))
                            throw new ArgumentException("Unknown option: " + a);
                        if (serverArg == null)
                            serverArg = a;
                        else
                            throw new ArgumentException("Unexpected positional arg: " + a);
                        break;
                }
            }

            if (!o.Unmount && !o.ShowVersion && serverArg != null)
            {
                ParseHostPort(serverArg, o);
            }

            return o;
        }

        static void ParseHostPort(string s, MountOptions o)
        {
            var colon = s.LastIndexOf(':');
            if (colon > 0 && colon < s.Length - 1)
            {
                o.Host = s.Substring(0, colon);
                int p;
                if (!int.TryParse(s.Substring(colon + 1), out p))
                    throw new ArgumentException("Invalid port in " + s);
                o.Port = p;
            }
            else
            {
                o.Host = s;
                o.Port = 8080;
            }
        }
    }
}