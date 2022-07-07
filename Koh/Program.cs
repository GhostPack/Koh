using System;
using System.Collections.Concurrent;

namespace Koh
{
    class Program
    {
        // the maximum number of unique tokens/logon sessions to capture
        public static int maxTokens = 1000;

        // whether we've been warned that we've hit max captured tokens
        public static bool maxWarned = false;

        static void Main(string[] args)
        {
            try
            {
                // Debug mode outputs additional output on the command line for the server
#if DEBUG
                bool DEBUG = true;
#else
                bool DEBUG = false;
#endif

                // password used for communications, super securez I know :)
                string password = "password";
                string pipeName = "imposecost";

                // thread safe dictionary for metadata, i.e., signaling we're exiting
                ConcurrentDictionary<string, int> meta = new ConcurrentDictionary<string, int>();
                meta["SignalExit"] = 0;
                meta["AcquireCredentialsHandleError"] = 0;

                // thread safe dictionary for session capture
                ConcurrentDictionary<string, Capture.CapturedSession> capturedSessions = new ConcurrentDictionary<string, Capture.CapturedSession>();

                // thread safe dictionary for sid filtering/updating
                ConcurrentDictionary<string, bool> filterSids = new ConcurrentDictionary<string, bool>();

                // thread safe dictionary for sids to exclude from capture
                ConcurrentDictionary<string, bool> excludeSids = new ConcurrentDictionary<string, bool>();

                Helpers.Logo();

                if (args.Length > 0)
                {
                    string command = args[0].ToLower();
                    Console.WriteLine($"\n  [*] Command: {command}");

                    for (int i = 1; i < args.Length; i++)
                    {
                        // any additional arguments -> assume they're domain group SIDs for filtering
                        if (Helpers.IsDomainSid(args[i]))
                        {
                            filterSids.TryAdd(args[i], true);
                        }
                        else
                        {
                            if(args[i].ToLower() == "/debug")
                            {
                                DEBUG = true;
                            }
                        }
                    }

                    if (command == "list")
                    {
                        // list all current logon sessions
                        Capture.Sessions(meta, capturedSessions, excludeSids, filterSids, false, false);
                    }
                    else if (command == "monitor")
                    {
                        // monitor a host for new logon sessions
                        PipeServer server = new PipeServer(pipeName, password, meta, capturedSessions, excludeSids, filterSids, "monitor", DEBUG);
                        server.Run();
                        Capture.Sessions(meta, capturedSessions, excludeSids, filterSids, true, false);
                    }
                    else if (command == "capture")
                    {
                        // monitor a host for new logon sessions and "capture" all sessions by negotiating a new token for each
                        PipeServer server = new PipeServer(pipeName, password, meta, capturedSessions, excludeSids, filterSids, "capture", DEBUG);
                        server.Run();
                        
                        Capture.Sessions(meta, capturedSessions, excludeSids, filterSids, true, true);
                    }
                    else
                    {
                        Helpers.Usage();
                    }
                }
                else
                {
                    Helpers.Usage();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"  [!] Unhandled terminating exception: {e}");
            }
        }
    }
}
