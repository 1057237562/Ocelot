﻿using System.CommandLine;

namespace Ocelot
{
    class Program
    {
        static string ipaddr = "127.0.0.1";
        static int port;
        static int sport;
        static int mode = 0;
        public static string user = "guest";
        public static string pass = "password";
        public static bool log = false;
        static void Main(string[] args)
        {
            var rootCommand = new RootCommand("A encrypted network proxy.");

            var ip = new Option<string?>("-addr", () => "127.0.0.1", "Set the address for proxy.");
            rootCommand.AddOption(ip);

            var Oport = new Option<string?>("-p", () => "3000", "Set the port number for proxy.");
            rootCommand.AddOption(Oport);

            var Osport = new Option<string?>("-sp", () => "3000", "Set the server port number for proxy.");
            rootCommand.AddOption(Osport);

            var Omode = new Option<string?>("-m", "Set the running mode. ( client / server )");
            rootCommand.AddOption(Omode);

            var Ouser = new Option<string?>("-u", () => "guest", "Set user for sessions");
            rootCommand.AddOption(Ouser);

            var Opass = new Option<string?>("-pass", () => "", "Set password for sessions");
            rootCommand.AddOption(Opass);

            var Olog = new Option<string?>("-log", () => "none", "Set log level");
            rootCommand.AddOption(Olog);

            rootCommand.SetHandler((a, b, c, d, e, f, g) =>
            {
                ipaddr = a!;
                port = int.Parse(b!);
                sport = int.Parse(c!);
                if (d == "server")
                {
                    mode = 1;
                }
                user = e!;
                pass = f!;
                if (g == "info")
                {
                    log = true;
                }
            }, ip, Oport, Osport, Omode, Ouser, Opass, Olog);

            rootCommand.Invoke(args);

            if (mode == 0)
            {
                ThreadPool.SetMaxThreads(Environment.ProcessorCount * 32, Environment.ProcessorCount * 32);
                Client client = new Client(ipaddr, sport, port);
            }
            else
            {
                ThreadPool.SetMaxThreads(Environment.ProcessorCount * 64, Environment.ProcessorCount * 64);
                Server server = new Server(port);
            }
        }
    }
}