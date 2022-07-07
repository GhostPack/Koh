using System;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;

namespace Koh
{
    class Creds
    {
        private const int MAX_TOKEN_SIZE = 12288;
        private const uint SEC_E_OK = 0;
        private const uint SEC_I_CONTINUE_NEEDED = 0x90312;
        private const int SECPKG_CRED_BOTH = 3;
        private const int ISC_REQ_CONNECTION = 0x00000800;
        private const int SECURITY_NATIVE_DREP = 0x10;

        public static Interop.SECURITY_HANDLE GetCredentialHandle(LUID luid, ConcurrentDictionary<string, int> meta = null)
        {
            // Acquires a credential handle for the specified logon session ID (LUID)

            IntPtr luidPtr = IntPtr.Zero;
            Interop.SECURITY_HANDLE cred = Interop.SECURITY_HANDLE.Empty;
            Interop.FILETIME clientLifeTime = new Interop.FILETIME();
            luidPtr = Marshal.AllocHGlobal(Marshal.SizeOf(luid));
            Marshal.StructureToPtr(luid, luidPtr, false);

            var res = Interop.AcquireCredentialsHandle(
                "",
                "Negotiate",
                SECPKG_CRED_BOTH,
                luidPtr,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                ref cred,
                ref clientLifeTime
            );
            if (res != SEC_E_OK)
            {
                if (res == 0x8009030e)
                {
                    Console.WriteLine($"  [X] AcquireCredentialsHandle for LUID {luid} failed. Error: SEC_E_NO_CREDENTIALS");
                }
                else
                {
                    Console.WriteLine($"  [X] AcquireCredentialsHandle for LUID {luid} failed. Error: 0x{res:x8}");
                }

                if (meta != null)
                {
                    meta["AcquireCredentialsHandleError"] = meta["AcquireCredentialsHandleError"] + 1;
                }
            }

            // // TODO: try to decipher the clientLifeTime struct
            //long fileTime = (long)((clientLifeTime.HighPart << 32) + clientLifeTime.LowPart);
            //Console.WriteLine($"[*] fileTime: {fileTime}");
            //DateTime dt = DateTime.FromFileTimeUtc(fileTime);
            //Console.WriteLine($"[*] Credential dt: {dt}");

            Marshal.FreeHGlobal(luidPtr);
            luidPtr = IntPtr.Zero;

            return cred;
        }

        
        public static string GetCredentialUserName(LUID luid, bool DEBUG = false)
        {
            // Return the true username for a credential in case we have a NewCredentials/Type 9 situation

            Interop.SECURITY_HANDLE cred = GetCredentialHandle(luid);

            if ((cred.HighPart == IntPtr.Zero) && (cred.LowPart == IntPtr.Zero))
            {
                return "";
            }

            if (DEBUG) Console.WriteLine($"DEBUG Successfully got a credential handle to LUID: {luid}");

            // SECPKG_CRED_ATTR_NAMES = 1
            uint ret = Interop.QueryCredentialsAttributes(ref cred, 1, out var credName);
            bool delSuccess = Interop.FreeCredentialsHandle(ref cred);

            if (ret != 0)
            {
                if (DEBUG) Console.WriteLine($"DEBUG Error running QueryCredentialsAttributes: {ret}");
                return "";
            }
            else
            {
                // get the username for the credential (i.e., for NewCredentials)
                return Marshal.PtrToStringAnsi(credName).Trim();
            }
        }

        public static IntPtr NegotiateToken(LUID luid, ConcurrentDictionary<string, int> meta, bool DEBUG = false)
        {
            // grabs a credential handle for a specified LUID and negotiates a usable token
            //  ref - https://mskb.pkisolutions.com/kb/180548

            SecBufferDesc ClientToken = new SecBufferDesc(MAX_TOKEN_SIZE);
            SecBufferDesc ClientToken2 = new SecBufferDesc(MAX_TOKEN_SIZE);
            SecBufferDesc ServerToken = new SecBufferDesc(MAX_TOKEN_SIZE);
            Interop.SECURITY_HANDLE ClientContext = new Interop.SECURITY_HANDLE();
            Interop.SECURITY_HANDLE ServerContext = new Interop.SECURITY_HANDLE();
            Interop.SECURITY_INTEGER ClientLifeTime;
            uint ContextAttributes = 0;
            IntPtr token = IntPtr.Zero;

            try
            {
                // Step 1 => acquire a credential handle to the specified logon session ID/LUID
                Interop.SECURITY_HANDLE cred = GetCredentialHandle(luid, meta);

                if ((cred.HighPart == IntPtr.Zero) && (cred.LowPart == IntPtr.Zero))
                {
                    return IntPtr.Zero;
                }

                if (DEBUG) Console.WriteLine($"DEBUG Successfully got a credential handle to LUID: {luid}");


                // Step 2 -> call InitializeSecurityContext() with the cred handle to start the "client" side of negotiation
                uint clientRes = Interop.InitializeSecurityContext(
                    ref cred,
                    IntPtr.Zero,
                    "",
                    ISC_REQ_CONNECTION,
                    0,
                    SECURITY_NATIVE_DREP,
                    IntPtr.Zero,
                    0,
                    out ClientContext,
                    out ClientToken,
                    out ContextAttributes,
                    out ClientLifeTime);
                if (clientRes != SEC_I_CONTINUE_NEEDED)
                {
                    Console.WriteLine($"  [X] First InitializeSecurityContext() failed: {clientRes}");
                    bool delSuccess1 = Interop.FreeCredentialsHandle(ref cred);
                    throw new Exception("InitializeSecurityContext failure");
                }


                // Step 2 -> call AcceptSecurityContext() with the client token, using the same credential
                uint serverRes = Interop.AcceptSecurityContext(
                    ref cred,
                    IntPtr.Zero,
                    ref ClientToken,
                    ISC_REQ_CONNECTION,
                    SECURITY_NATIVE_DREP,
                    out ServerContext,
                    out ServerToken,
                    out ContextAttributes,
                    out ClientLifeTime
                    );
                if (serverRes != SEC_I_CONTINUE_NEEDED)
                {
                    Console.WriteLine($"  [X] First AcceptSecurityContext() failed: {serverRes}");
                    bool delSuccess1 = Interop.FreeCredentialsHandle(ref cred);
                    throw new Exception("First AcceptSecurityContext failure");
                }


                // Step 3 -> call InitializeSecurityContext() with the server token
                clientRes = Interop.InitializeSecurityContext(
                    ref cred,
                    ref ClientContext,
                    "",
                    ISC_REQ_CONNECTION,
                    0,
                    SECURITY_NATIVE_DREP,
                    ref ServerToken,
                    0,
                    out ClientContext,
                    out ClientToken2,
                    out ContextAttributes,
                    out ClientLifeTime);
                if ((clientRes != SEC_I_CONTINUE_NEEDED) && (clientRes != SEC_E_OK))
                {
                    Console.WriteLine($"  [X] Second InitializeSecurityContext() failed: {clientRes}");
                    bool delSuccess1 = Interop.FreeCredentialsHandle(ref cred);
                    throw new Exception("Second InitializeSecurityContext failure");
                }


                // Step 4 -> call AcceptSecurityContext() with the client token
                serverRes = Interop.AcceptSecurityContext(
                    ref cred,
                    ref ServerContext,
                    ref ClientToken2,
                    ISC_REQ_CONNECTION,
                    SECURITY_NATIVE_DREP,
                    out ServerContext,
                    out ServerToken,
                    out ContextAttributes,
                    out ClientLifeTime
                    );
                if (serverRes != SEC_E_OK)
                {
                    Console.WriteLine($"  [X] Second AcceptSecurityContext() failed: {serverRes}");
                    bool delSuccess1 = Interop.FreeCredentialsHandle(ref cred);
                    throw new Exception("Second AcceptSecurityContext failure");
                }


                // Step 4 -> turn the server context into a usable token
                uint status = Interop.QuerySecurityContextToken(ServerContext, out token);
                if (status != 0)
                {
                    Console.WriteLine("  [X] QuerySecurityContextToken() failed: {0}", status);
                    bool delSuccess1 = Interop.FreeCredentialsHandle(ref cred);
                    throw new Exception("QuerySecurityContextToken failure");
                }

                if (DEBUG) Console.WriteLine($"DEBUG Successfully negotiated credential to token: {token}");

                bool delSuccess2 = Interop.FreeCredentialsHandle(ref cred);
            }
            catch(Exception e)
            {
                if (e.Message != "fail")
                {
                    Console.WriteLine($"  [X] Exception: {e}");
                }
            }
            finally
            {
                bool del2Success = Interop.DeleteSecurityContext(ref ClientContext);
                bool del3Success = Interop.DeleteSecurityContext(ref ServerContext);

                ClientToken.Dispose();
                ClientToken2.Dispose();
                ServerToken.Dispose();
            }

            return token;
        }
    }
}
