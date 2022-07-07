using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Koh
{
    class Find
    {
        public struct FoundSession
        {
            // represents a found/enumerated logon session
            public string UserName;
            public string CredentialUserName;
            public string Luid;
            public string SID;
            public Interop.SECURITY_LOGON_TYPE LogonType;
            public string AuthPackage;

            public FoundSession(string userName, string credentialUserName, string luid, string sid, Interop.SECURITY_LOGON_TYPE logonType, string authPackage)
            {
                UserName = userName;
                CredentialUserName = credentialUserName;
                Luid = luid;
                SID = sid;
                LogonType = logonType;
                AuthPackage = authPackage;
            }
        }

        public static Dictionary<string, FoundSession> LogonSessions(bool DEBUG = false)
        {
            // finds all logon sessions that match our specific criteria:
            //      - user SID is domain formatted
            //      - logonType != Network

            var logonSessions = new Dictionary<string, FoundSession>();

            try
            {
                var systime = new DateTime(1601, 1, 1, 0, 0, 0, 0); // win32 systemdate

                // get an array of pointers to LUIDs
                var ret = Interop.LsaEnumerateLogonSessions(out var count, out var luidPtr);

                if (ret != 0)
                {
                    Console.WriteLine($"  [!] Error with calling LsaEnumerateLogonSessions: {ret}");
                    return logonSessions;
                }

                for (ulong i = 0; i < count; i++)
                {
                    ret = Interop.LsaGetLogonSessionData(luidPtr, out var sessionData);
                    if (ret != 0)
                    {
                        Console.WriteLine($"  [!] Error with calling LsaGetLogonSessionData on LUID {luidPtr}: {ret}");
                        continue;
                    }

                    var data = (Interop.SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(sessionData, typeof(Interop.SECURITY_LOGON_SESSION_DATA));

                    // if we have a valid logon
                    if (data.PSiD != IntPtr.Zero)
                    {
                        // get the account username
                        var username = Marshal.PtrToStringUni(data.Username.Buffer).Trim();

                        // convert the security identifier of the user
                        var sid = new System.Security.Principal.SecurityIdentifier(data.PSiD);

                        // domain for this account
                        var domain = Marshal.PtrToStringUni(data.LoginDomain.Buffer).Trim();

                        // authentication package
                        var authPackage = Marshal.PtrToStringUni(data.AuthenticationPackage.Buffer).Trim();

                        // logon type
                        var logonType = (Interop.SECURITY_LOGON_TYPE)data.LogonType;

                        // datetime the session was logged in
                        var logonTime = systime.AddTicks((long)data.LoginTime);

                        // user's logon server
                        var logonServer = Marshal.PtrToStringUni(data.LogonServer.Buffer).Trim();

                        // logon server's DNS domain
                        var dnsDomainName = Marshal.PtrToStringUni(data.DnsDomainName.Buffer).Trim();

                        // user principalname
                        var upn = Marshal.PtrToStringUni(data.Upn.Buffer).Trim();

                        var logonID = "";
                        try { logonID = data.LoginID.LowPart.ToString(); }
                        catch { }

                        // get the credential username (i.e., for NewCredentials)
                        var credentialUserName = Creds.GetCredentialUserName(new LUID(logonID), DEBUG);

                        var userSID = "";
                        try { userSID = sid.Value; }
                        catch { }

                        // domain users only (or NewCredentials/Type 9)
                        if (Helpers.IsDomainSid(userSID) || logonType == Interop.SECURITY_LOGON_TYPE.NewCredentials)
                        {
                            // Network logon types aren't going to have any credentials
                            if (logonType != Interop.SECURITY_LOGON_TYPE.Network)
                            {
                                string identifier = userSID + credentialUserName + authPackage + logonType;

                                FoundSession foundSession = new FoundSession($"{domain}\\{username}", credentialUserName, logonID, userSID, logonType, authPackage);

                                if (!logonSessions.ContainsKey(identifier))
                                {
                                    logonSessions.Add(identifier, foundSession);
                                }
                                else
                                {
                                    logonSessions[identifier] = foundSession;
                                }
                            }
                        }
                    }

                    // move the pointer forward
                    luidPtr = (IntPtr)((long)luidPtr.ToInt64() + Marshal.SizeOf(typeof(LUID)));
                    Interop.LsaFreeReturnBuffer(sessionData);
                }
                Interop.LsaFreeReturnBuffer(luidPtr);
            }
            catch(Exception e)
            {
                Console.WriteLine($"  [!] Error in LogonSessions(): {e}");
            }

            return logonSessions;
        }
    }
}
