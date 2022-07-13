using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace Koh
{
    class Helpers
    {
        private const string Version = "1.0.0";

        public static void Logo()
        {
            Console.WriteLine("\n __  ___   ______    __    __  ");
            Console.WriteLine("|  |/  /  /  __  \\  |  |  |  | ");
            Console.WriteLine("|  '  /  |  |  |  | |  |__|  | ");
            Console.WriteLine("|    <   |  |  |  | |   __   | ");
            Console.WriteLine("|  .  \\  |  `--'  | |  |  |  | ");
            Console.WriteLine("|__|\\__\\  \\______/  |__|  |__| ");
            Console.WriteLine($"                     v{Version}\n");
        }

        public static void Usage()
        {
            Console.WriteLine("\n  Koh.exe <list | monitor | capture> [GroupSID... GroupSID2 ...]\n");
        }

        public static string MD5(string input)
        {
            // Use input string to calculate MD5 hash
            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                // Convert the byte array to hexadecimal string
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("X2"));
                }
                return sb.ToString().ToLower();
            }
        }

        public static string GetMachineName()
        {
            // grab the current computer NETBIOS name

            StringBuilder name = new StringBuilder(260);
            int nSize = 260;
            if (!Interop.GetComputerName(name, ref nSize))
            {
                var ex = new Win32Exception(Marshal.GetLastWin32Error());
                Console.WriteLine($"  [X] Error retrieving computer name via GetComputerName(): {ex.Message} ({ex.ErrorCode})");
            }
            return $"{name}";
        }

        public static bool CheckTokenForGroup(IntPtr token, string groupSID)
        {
            // Takes a token pointer and a group SID string, and returns if the given token has that specific group present
            //  Used for group SID filtering

            List<string> groupSids = GetTokenGroups(token);
            return groupSids.Contains(groupSID);
        }

        public static LUID GetTokenOrigin(IntPtr token)
        {
            // gets the origin LUID for the specified token

            IntPtr pOrigin = Helpers.GetTokenInfo(token, Interop.TOKEN_INFORMATION_CLASS.TokenOrigin);
            Interop.TOKEN_ORIGIN origin = (Interop.TOKEN_ORIGIN)Marshal.PtrToStructure(pOrigin, typeof(Interop.TOKEN_ORIGIN));
            Marshal.FreeHGlobal(pOrigin);
            return origin.LoginID;
        }

        public static List<string> GetTokenGroups(IntPtr token)
        {
            // returns an arraylist of all of the group SIDs present for a specified token

            List<string> groupSids = new List<string>();

            try
            {
                IntPtr pGroups = GetTokenInfo(token, Interop.TOKEN_INFORMATION_CLASS.TokenGroups);

                Interop.TOKEN_GROUPS groups = (Interop.TOKEN_GROUPS)Marshal.PtrToStructure(pGroups, typeof(Interop.TOKEN_GROUPS));
                string[] userSIDS = new string[groups.GroupCount];
                int sidAndAttrSize = Marshal.SizeOf(new Interop.SID_AND_ATTRIBUTES());

                for (int i = 0; i < groups.GroupCount; i++)
                {
                    Interop.SID_AND_ATTRIBUTES sidAndAttributes = (Interop.SID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                        new IntPtr(pGroups.ToInt64() + i * sidAndAttrSize + IntPtr.Size), typeof(Interop.SID_AND_ATTRIBUTES));

                    string sidString = "";
                    Interop.ConvertSidToStringSid(sidAndAttributes.Sid, out sidString);

                    groupSids.Add(sidString);
                }

                Marshal.FreeHGlobal(pGroups);
            }
            catch { }

            return groupSids;
        }

        public static IntPtr GetTokenInfo(IntPtr token, Interop.TOKEN_INFORMATION_CLASS informationClass)
        {
            // Wrapper that uses GetTokenInformation to retrieve the specified TOKEN_INFORMATION_CLASS

            var TokenInfLength = 0;

            // first call gets length of TokenInformation
            var Result = Interop.GetTokenInformation(token, informationClass, IntPtr.Zero, TokenInfLength, out TokenInfLength);
            var TokenInformation = Marshal.AllocHGlobal(TokenInfLength);
            Result = Interop.GetTokenInformation(token, informationClass, TokenInformation, TokenInfLength, out TokenInfLength);

            if (!Result)
            {
                Marshal.FreeHGlobal(TokenInformation);
                throw new Exception("Unable to get token info.");
            }

            return TokenInformation;
        }

        public static bool IsDomainSid(string sid)
        {
            // Returns true if the SID string matches a domain SID pattern

            string pattern = @"^S-1-[0-59]-\d{2}-\d{8,10}-\d{8,10}-\d{8,10}-[1-9]\d{2}";
            Match m = Regex.Match(sid, pattern, RegexOptions.IgnoreCase);
            return m.Success;
        }

        public static bool IsHighIntegrity()
        {
            // Returns true if the current process is running with administrative privs in a high integrity context

            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static bool GetSystem()
        {
            // helper to elevate to SYSTEM so we can get SeTcbPrivilege

            if (IsHighIntegrity())
            {
                IntPtr hToken = IntPtr.Zero;

                // Open winlogon's token with TOKEN_DUPLICATE accesss so we can make a copy of the token with DuplicateToken
                Process[] processes = Process.GetProcessesByName("winlogon");
                IntPtr handle = processes[0].Handle;

                // TOKEN_DUPLICATE = 0x0002
                bool success = Interop.OpenProcessToken(handle, 0x0002, out hToken);
                if (!success)
                {
                    Console.WriteLine("  [!] GetSystem() - OpenProcessToken failed!");
                    return false;
                }

                // make a copy of the NT AUTHORITY\SYSTEM token from winlogon
                // 2 == SecurityImpersonation
                IntPtr hDupToken = IntPtr.Zero;
                success = Interop.DuplicateToken(hToken, 2, ref hDupToken);
                if (!success)
                {
                    Interop.CloseHandle(hToken);
                    Console.WriteLine("  [!] GetSystem() - DuplicateToken failed!");
                    return false;
                }

                success = Interop.ImpersonateLoggedOnUser(hDupToken);
                if (!success)
                {
                    Interop.CloseHandle(hToken);
                    Interop.CloseHandle(hDupToken);
                    Console.WriteLine("  [!] GetSystem() - ImpersonateLoggedOnUser failed!");
                    return false;
                }

                // clean up the handles we created
                Interop.CloseHandle(hToken);
                Interop.CloseHandle(hDupToken);

                if (!IsSystem())
                {
                    return false;
                }

                return true;
            }
            else
            {
                return false;
            }
        }

        public static bool IsSystem()
        {
            // Returns true if the current context is "NT AUTHORITY\SYSTEM"

            var currentSid = WindowsIdentity.GetCurrent().User;
            return currentSid.IsWellKnown(WellKnownSidType.LocalSystemSid);
        }
    }
}
