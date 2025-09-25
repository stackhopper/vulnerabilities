# Summary

A malicious application can receive the Full Disk Access permissions meant for a legitimate application, when both applications share the same bundle ID. This affects macOS 15.6.1 and macOS Tahoe 26 Beta 8.
# Explanation

Given both a legitimate and a malicious applications with the same bundle ID, three scenarios can lead to the malicious application receiving the entitlements for the legitimate application.
## Scenario 1

If the **malicious** application is registered in the LaunchServices private framework using the `lsregister` binary before giving the legitimate application Full Disk Access permissions via `System Settings.app`, the following behaviors are observed:

* Upon adding the legitimate application via the '+' sign in the `Privacy and Security` -> `Full Disk Access` section of `System Settings.app`, the legitimate application's entry will open Finder on the correct path upon right-clicking the new entry -> 'Show on Finder'
* If the malicious application is ran, any action involving tccd will toggle off the Full Disk Access permission on `System Settings.app`
* Upon toggling back the Full Disk Access permission on `System Settings.app` for the legitimate app, the Full Disk Access permission will be given to the malicious application instead.
## Scenario 2 

If the **legitimate** application is registered in the LaunchServices private framework using the `lsregister` binary before giving the legitimate application Full Disk Access permissions via `System Settings.app`, the following behaviors are observed:

* When the **malicious** application is added to the Full Disk Access section on `System Settings.app`, the entry will be rewritten to the name of the **legitimate** application registered via `lsregister`
* On the newly added Full Disk Access entry for the second application, upon right-clicking the new entry -> 'Show on Finder', it will show the path for the legitimate application, when in reality the malicious application was selected 
* Upon executing the legitimate app, the Full Disk Access permission in `System Settings.app` is toggled off, effectively removing the permissions.
## Scenario 3

If both the malicious application and the legitimate application are also registered via `lsregister` before granting the Full Disk permission on `System Settings.app` (like a user would do if the application requires it), the following behaviors are observed:

* `System Settings.app` will enable Full Disk Access grants for **both** applications
* `System Settings.app` will only display the **legitimate** application's name and path on its Full Disk Access entry 
* `System Settings.app` will **NOT** display the malicious application on the Full Disk Access granted applications list.

**Note:** the demo application tries to list the contents of `/Library/Application Support/com.apple.TCC/`, which can't be listed without full Disk Access permissions on a macOS system with SIP enabled.

# Behaviors identification

The most critical behaviors shown in the video evidence are explained below.
### 1. Bundle identificators confusion

To my best knowledge, the core bug resides in the `CoreFoundation``_CFBundleCopyInfoPlistURL` method.
From this faulting method, multiple resources are affected by the bug. Here's a mostly complete list of methods affected by the bugged function:

```
-[TCCDAccessIdentity staticCode]
	|_ -[TCCDBundle bundleURL]
		  |_ CoreFoundation``CFBundleCopyBundleURL
		  	|_ Security``Security:CodeSigning::BundleDiskRep::copyCanonicalPath
		  		|_ CoreFoundation``CFBundleCopyExecutableURL
		  			|_ CoreFoundation``_CFBundleCopyExecutableURLInDirectory2
		  				|_ CoreFoundation``_CFBundleCopyExecutableURLRaw
			  				|_ CoreFoundation``CFURLCopyFileSystemPath
				  				|_ CoreFoundation``CFURLCreateWithString
										|_ CoreFoundation``CFBundleGetInfoDictionary
```

### 2. Full Disk access permission granting to malicious application

`-[TCCDAccessIdentity initWithIdentifier:type:executableURL:SDKVersion:platformType:]` fetches the previously registered bundle ID via `lsregister`; please notice that the bug is triggered between `-[TCCDAccessIdentity staticCode]:` and `-[TCCDAccessIdentity designatedRequirementData]`. After more reversing and backtracking, it was then concluded that the arbitrary grant is triggered upon *calling* **`-[TCCDBundle bundleURL]`** (tccd`___lldb_unnamed_symbol924` for both macOS Sequoia 15.6.1 and Tahoe 26.0) and then following the normal permission granting mechanism. On the Security Framework, the issue resides at `Security``SecStaticCodeCreateWithPath`.

After a successful execution, the `-[TCCDAccessIdentity staticCode]` method will produce two `staticCode` objects for application signature verification, one for the malicious application and another for the legitimate application (this can be seen on `Console.log`). 

```
102f29c10 0x102f29c10 tccd!-[TCCDAccessIdentity matchesCodeRequirement:]
19f1d5438 0x19f1d5438 Security!Security::SecCFObject::handle(bool)
102f29e8c 0x102f29e8c tccd!-[TCCDAccessIdentity matchesCodeRequirementData:]
102f2a2cc 0x102f2a2cc tccd!-[TCCDAccessIdentity deriveWithAttributionChain:platformBinaryFromApple:signingStatus:entitlements:]
102f2a4ec 0x102f2a4ec tccd!0x224ec (0x1000224ec)
102f5bc48 0x102f5bc48 tccd!-[TCCDPlatformMacOS promptingPolicyForIdentity:accessingService:withAttributionChain:]
102f18414 0x102f18414 tccd!0x10414 (0x100010414)
102f1c2d4 0x102f1c2d4 tccd!0x142d4 (0x1000142d4)
102f1c2d4 0x102f1c2d4 tccd!0x142d4 (0x1000142d4)
19baa0e2c 0x19baa0e2c libxpc.dylib!_xpc_dictionary_look_up
102f144e8 0x102f144e8 tccd!0xc4e8 (0x10000c4e8)
102f54a38 0x102f54a38 tccd!-[TCCDRequestContext initWithRequestMessage:forServer:error:]
102f0f184 0x102f0f184 tccd!0x7184 (0x100007184)
19bbec9a0 0x19bbec9a0 libdispatch.dylib!_os_object_alloc_realized
19baa416c 0x19baa416c libxpc.dylib!_xpc_dictionary_create_from_received_message
19baa4040 0x19baa4040 libxpc.dylib!_xpc_graph_unpack_impl
```

_Fig. 1 - Backtrack log from Frida upon breaking on `-[TCCDAccessIdentity staticCode]`_

<img width="2077" height="347" alt="Image" src="https://github.com/user-attachments/assets/06c2d9ec-1ece-4f5e-b8f7-cc91c3621cde" />

_Fig. 2 - Double `staticCode` objects granted for both applications_

It's worth noting that the bugged method's output is replicated throughout other relevant methods related to the permission granting:

`-[TCCDAccessIdentity initWithMessage:]`
`-[TCCDBundle initWithIdentifier:]`

```
104dd63c0 0x104dd63c0 tccd!+[TCCDBundle bundleWithIdentifier:]initWithIdentifier
104dcc5f4 0x104dcc5f4 tccd!-[TCCDAccessIdentity initWithIdentifier:type:executableURL:SDKVersion:platformType:]
104dc9618 0x104dc9618 tccd!-[TCCDCodeIdentity accessIdentity]
104db1fb0 0x104db1fb0 tccd!0x5fb0 (0x100005fb0)
104e04888 0x104e04888 tccd!-[TCCDProcess dealloc]
18d2ebe00 0x18d2ebe00 libobjc.A.dylib!object_cxxDestructFromClass(objc_object*, objc_class*)
104db3c5c 0x104db3c5c tccd!0x7c5c (0x100007c5c)
18d5686f0 0x18d5686f0 libsystem_c.dylib!__vfprintf
18d51c9a0 0x18d51c9a0 libdispatch.dylib!_os_object_alloc_realized
18d3d416c 0x18d3d416c libxpc.dylib!_xpc_dictionary_create_from_received_message
18d3d4040 0x18d3d4040 libxpc.dylib!_xpc_graph_unpack_impl
18d6918d4 0x18d6918d4 libsystem_kernel.dylib!kdebug_trace
18d3d3cbc 0x18d3d3cbc libxpc.dylib!xpc_receive_mach_msg
18d3d912c 0x18d3d912c libxpc.dylib!_xpc_connection_mach_event
18d53e340 0x18d53e340 libdispatch.dylib!_dispatch_event_loop_drain
18d5358a4 0x18d5358a4 libdispatch.dylib!_dispatch_client_callout4
```

_Fig. 3 - Frida thread backtrace log upon breaking on `-[TCCDBundle initWithURL:]` showing the affected methods being called_

### 3. Full Disk Access entry application name spoofing

The `tccd` method with symbol tccd`___lldb_unnamed_symbol539` starts the `tccd` transaction with the chosen bundle's full path (via UI file picker):

<img width="891" height="529" alt="Image" src="https://github.com/user-attachments/assets/70ccf1c6-c454-49fd-920c-5747a2ef4ff1" />

_Fig. 4 - Scenario 2 reproduction via `lldb` session (data stored on register **x0**)_

Afterwards, we see that the bug manifests from the CoreFoundation `_CFBundleCopyInfoPlistURL` method, which renders the bundle ID registered with `lsregister` in `System Settings.app`. The behavior can be seen upon replicating scenario #2 (adding `fda-alternative.app` to the Full Disk Access allowed applications list on `System Settings.app`): with the following breakpoint in `lldb`:

```
breakpoint set --name _CFBundleCopyInfoPlistURL --condition '[(NSString *)[(__bridge NSURL *)CFBundleCopyBundleURL($x0) path] isEqualToString:@"/Users/research/Desktop/TCC-FDA-Original/fda-original.app"]' -G1
```

<a href="https://youtu.be/oSgiS9h60NI"><img width="1593" height="1061" alt="Image" src="https://github.com/user-attachments/assets/fc3cd6ea-d299-430d-b1b6-7a796ad804e7" /></a>
_Fig. 5 - Thread backtrace of the spoofing behavior caused by `_CFBundleCopyInfoPlistURL` - Click on image for the video_

# Expected results

Different applications with the same bundle ID should be properly handled and different permissions be given based on what each application requested.

# Actual results

A confused deputy attack can be performed targeting `System Settings.app`and the TCC daemon, providing a malicious application with the same bundle a legitimate application's permissions.

# Proofs of Concept

Available upon request.

------
# Supporting evidence

1. Debug logs from `Console.app` showing the bug being triggered:

```
Timestamp Thread Type Activity PID TTL
2025-09-12 08:35:25.532478-0300 0x22d5 Default 0x14618 152 0 tccd: [com.apple.TCC:access] REQUEST: tccd_uid=0, sender_pid=666, sender_uid=501, sender_auid=501, function=TCCAccessSetInternal, msgID=666.144
2025-09-12 08:35:25.532651-0300 0x22d5 Info 0x14618 152 0 tccd: [com.apple.TCC:access] REQUEST_MSG: msgID=666.144, msg={
	service="kTCCServiceSystemPolicyAllFiles"
	modDate=0 (0x0)
	flags=0 (0x0)
	function="TCCAccessSetInternal"
	bundle_url="file:///Users/research/Desktop/TCC-FDA-Legitimate/fda-legitimate.app/"
	noKill=false
	target_token={NULL}
	TCCD_MSG_ID="666.144"
	indirect_object_code_requirement=<xpc_null>
	client_type="bundle"
	indirect_object_identifier=<xpc_null>
	indirect_object_type=<xpc_null>
	code_requirement=<xpc_null>
	granted=true
	client="com.stackhopper.fda"
}

2025-09-12 08:35:25.533096-0300 0x22d5 Info 0x14618 152 0 tccd: [com.apple.TCC:access] AttributionChain: requesting={TCCDProcess: identifier=com.apple.settings.PrivacySecurity.extension, pid=666, auid=501, euid=501, binary_path=/System/Library/ExtensionKit/Extensions/SecurityPrivacyExtension.appex/Contents/MacOS/SecurityPrivacyExtension},
2025-09-12 08:35:25.533111-0300 0x22d5 Debug 0x14618 152 0 tccd: [com.apple.TCC:access] Process com.apple.settings.PrivacySecurity.extension[666] is a composition manager.
2025-09-12 08:35:25.533321-0300 0x22d5 Info 0x14618 152 0 tccd: [com.apple.TCC:access] AttributionChain: requesting={TCCDProcess: identifier=com.apple.settings.PrivacySecurity.extension, pid=666, auid=501, euid=501, binary_path=/System/Library/ExtensionKit/Extensions/SecurityPrivacyExtension.appex/Contents/MacOS/SecurityPrivacyExtension},
2025-09-12 08:35:25.533625-0300 0x22d5 Debug 0x14618 152 0 tccd: [com.apple.TCC:access] -[TCCDAccessIdentity initWithMessage:]: bundle:<TCCDBundle: bundleID=com.stackhopper.fda, version=1, path=/Users/research/Desktop/TCC-FDA-Legitimate/fda-legitimate.app>; for: com.stackhopper.fda with url: file:///Users/research/Desktop/TCC-FDA-Legitimate/fda-legitimate.app/
2025-09-12 08:35:25.535138-0300 0x22d5 Default 0x14618 152 0 tccd: [com.apple.TCC:access] -[TCCDAccessIdentity staticCode]: static code for: identifier com.stackhopper.fda, type: 0: 0xa082b8900 at /Users/research/Desktop/TCC-FDA-Legitimate/fda-legitimate.app
2025-09-12 08:35:25.535870-0300 0x22d5 Debug 0x14618 152 0 tccd: [com.apple.TCC:access] -[TCCDAccessIdentity designatedRequirementData]: DR for identifier com.stackhopper.fda with static code 0xa082b8900: cdhash H"3f727b2f4f9e5f96b62ed7c8623584c200ed688e"
2025-09-12 08:35:25.535940-0300 0x22d5 Info 0x14618 152 0 tccd: [com.apple.TCC:access] <TCCDProcess: identifier=com.apple.settings.PrivacySecurity.extension, pid=666> has the com.apple.private.tcc.manager.access.modify entitlement for service kTCCServiceAll (composed to parent: (null))
2025-09-12 08:35:25.535981-0300 0x22d5 Debug 0x14618 152 0 tccd: [com.apple.TCC:access] Process com.apple.settings.PrivacySecurity.extension[666] is a composition manager.
2025-09-12 08:35:25.536032-0300 0x22d5 Debug 0x14618 152 0 tccd: [com.apple.TCC:access] -[TCCDServer canProcess:manageESClientServiceWith:]: com.apple.settings.PrivacySecurity.extension is allowed to modify kTCCServiceEndpointSecurityClient records
2025-09-12 08:35:25.539582-0300 0x22d5 Info 0x14618 152 0 tccd: [com.apple.TCC:access] Update Access Record: kTCCServiceSystemPolicyAllFiles for com.stackhopper.fda to Allowed (System Set) (v1) at 1757676925 (2025-09-12 11:35:25 +0000)
	CodeReq: cdhash H"3f727b2f4f9e5f96b62ed7c8623584c200ed688e"
	Indirect : Unused
2025-09-12 08:35:25.540944-0300 0x22d5 Info 0x14618 152 0 tccd: [com.apple.TCC:access] -[TCCDAccessIdentity designatedRequirementData]: self.bundle=0xa082d80f0, bundle:<TCCDBundle: bundleID=com.stackhopper.fda, version=1, path=/Users/research/TCC-FDA-Alternative/fda-alternative-old.app>; for: com.stackhopper.fda, URL: (null), (null)
2025-09-12 08:35:25.540993-0300 0x22d5 Info 0x14618 152 0 tccd: [com.apple.TCC:access] Analytics Event preparing: com.apple.TCC.authorization_action
2025-09-12 08:35:25.543421-0300 0x22d5 Info 0x14618 152 0 tccd: [com.apple.TCC:access] reported bundle metrics for client: <private>
2025-09-12 08:35:25.543482-0300 0x22d5 Debug 0x14618 152 0 tccd: [com.apple.TCC:access] -[TCCDServer publishAccessChangedEvent:forService:client:clientType:authValue:authReason:andKillClient:attributionChain:]: event_type=2, service=<private>, client=<private>, client_type=0, auth_value=2, kill_client=1
2025-09-12 08:35:25.543559-0300 0x22d5 Default 0x14618 152 0 tccd: [com.apple.TCC:access] Posted notification: <private>
2025-09-12 08:35:25.543633-0300 0x22d5 Info 0x14618 152 0 tccd: [com.apple.TCC:access] REPLY_MSG: msg={
	result=true
}
2025-09-12 08:35:25.543669-0300 0x22d5 Default 0x14618 152 0 tccd: [com.apple.TCC:access] REPLY: (0) function=TCCAccessSetInternal, msgID=666.144
2025-09-12 08:35:25.544230-0300 0x22e5 Default 0x14618 152 0 tccd: [com.apple.TCC:events] Publishing <TCCDEvent: type=Modify, service=kTCCServiceSystemPolicyAllFiles, identifier_type=Bundle ID, identifier=com.stackhopper.fda> to 0 subscribers: {
}
[...]
2025-09-12 08:35:25.532405-0300 0x1676 Info 0x14618 666 0 SecurityPrivacyExtension: (TCC) [com.apple.TCC:access] SEND: 0/7 synchronous to com.apple.tccd.system: request: msgID=666.144, function=TCCAccessSetInternal, service=kTCCServiceSystemPolicyAllFiles, client=com.stackhopper.fda,
2025-09-12 08:35:25.543747-0300 0x1676 Info 0x14618 666 0 SecurityPrivacyExtension: (TCC) [com.apple.TCC:access] RECV: synchronous reply <dictionary: 0x60000336a940> { count = 1, transaction: 0, voucher = 0x0, contents =
	"result" => <bool: 0x1fc082830>: true
}
```

2. Post-bug trigger listing of applications with `kTCCServiceSystemPolicyAllFiles` permissions (shortened down to relevant logs only) on `System Settings.app`, where the malicious bundle ID is shown on the `tccd` message log - meanwhile the legitimate bundle ID is displayed on the `System Settings.app` GUI list, as shown on scenarios #1 and #2.

```
2025-09-12 08:35:25.586379-0300 0x22e5 Default 0x14359 152 0 tccd: [com.apple.TCC:access] REQUEST: tccd_uid=0, sender_pid=159, sender_uid=88, sender_auid=-1, function=TCCAccessRequest, msgID=159.126
2025-09-12 08:35:25.586457-0300 0x22e5 Info 0x14359 152 0 tccd: [com.apple.TCC:access] REQUEST_MSG: msgID=159.126, msg={
	require_purpose=<xpc_null>
	service="kTCCServiceListenEvent"
	function="TCCAccessRequest"
	preflight=true
	target_token={pid:655, auid:501, euid:501}
	TCCD_MSG_ID="159.126"
	background_session=false
}

2025-09-12 08:35:25.586738-0300 0x22e5 Info 0x14359 152 0 tccd: [com.apple.TCC:access] AttributionChain: accessing={TCCDProcess: identifier=com.apple.systempreferences, pid=655, auid=501, euid=501, binary_path=/System/Applications/System Settings.app/Contents/MacOS/System Settings}, requesting={TCCDProcess: identifier=com.apple.WindowServer, pid=159, auid=88, euid=88, binary_path=/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/WindowServer},
2025-09-12 08:35:25.586792-0300 0x22e5 Info 0x14359 152 0 tccd: [com.apple.TCC:access] <TCCDProcess: identifier=com.apple.WindowServer, pid=159> has the com.apple.private.tcc.manager.check-by-audit-token entitlement for service kTCCServiceListenEvent (composed to parent: (null))
2025-09-12 08:35:25.587027-0300 0x22e5 Info 0x14359 152 0 tccd: [com.apple.TCC:access] AttributionChain: accessing={TCCDProcess: identifier=com.apple.systempreferences, pid=655, auid=501, euid=501, binary_path=/System/Applications/System Settings.app/Contents/MacOS/System Settings}, requesting={TCCDProcess: identifier=com.apple.WindowServer, pid=159, auid=88, euid=88, binary_path=/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/WindowServer},
2025-09-12 08:35:25.587078-0300 0x22e5 Default 0x14359 152 0 tccd: [com.apple.TCC:access] AUTHREQ_CTX: msgID=159.126, function=<private>, service=kTCCServiceListenEvent, preflight=yes, query=1, client_dict=(null), daemon_dict=<private>
2025-09-12 08:35:25.587144-0300 0x22e5 Default 0x14359 152 0 tccd: [com.apple.TCC:access] AUTHREQ_ATTRIBUTION: msgID=159.126, attribution={accessing={TCCDProcess: identifier=com.apple.systempreferences, pid=655, auid=501, euid=501, binary_path=/System/Applications/System Settings.app/Contents/MacOS/System Settings}, requesting={TCCDProcess: identifier=com.apple.WindowServer, pid=159, auid=88, euid=88, binary_path=/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/WindowServer}, },
2025-09-12 08:35:25.587193-0300 0x22e5 Info 0x14359 152 0 tccd: [com.apple.TCC:access] <TCCDProcess: identifier=com.apple.WindowServer, pid=159> has the com.apple.private.tcc.manager.check-by-audit-token entitlement for service kTCCServiceListenEvent (composed to parent: (null))
2025-09-12 08:35:25.587260-0300 0x22e5 Default 0x14359 152 0 tccd: [com.apple.TCC:access] requestor: TCCDProcess: identifier=com.apple.WindowServer, pid=159, auid=88, euid=88, binary_path=/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/WindowServer is checking access for accessor TCCDProcess: identifier=com.apple.systempreferences, pid=655, auid=501, euid=501, binary_path=/System/Applications/System Settings.app/Contents/MacOS/System Settings

2025-09-12 08:35:25.588357-0300 0x22e5 Debug 0x14359 152 0 tccd: [com.apple.TCC:access] IDENTITY_ATTRIBUTION: starting for: /System/Applications/System Settings.app/Contents/MacOS/System Settings

2025-09-12 08:35:25.589117-0300 0x22e5 Info 0x14359 152 0 tccd: [com.apple.TCC:access] IDENTITY_ATTRIBUTION: /System/Applications/System Settings.app/Contents/MacOS/System Settings[159]: from cache: = com.apple.systempreferences, type 0 (75/178)

2025-09-12 08:35:25.589160-0300 0x22e5 Default 0x14359 152 0 tccd: [com.apple.TCC:access] AUTHREQ_SUBJECT: msgID=159.126, subject=com.apple.systempreferences,

2025-09-12 08:35:25.589137-0300 0x2305 Info 0x14619 152 0 tccd: [com.apple.TCC:access] REPLY_MSG: msg={
[...]
kTCCServiceSystemPolicyAllFiles=
[0] = {
	bundle="file:///Users/research/TCC-FDA-Alternative/fda-alternative.app/"
	session_pid_version=0 (0x0)
	session_pid=0 (0x0)
	has_prompted_for_allow=false
	bundle_id="com.stackhopper.fda"
	auth_value=2 (0x2)
	last_modified=1757676925 (0x68c4057d)
	[...]
```

# Conclusion

While the chain as a whole was deemed unexploitable under normal circumnstances, in my opinion the three bugs remain valid separately:

* There's a confused deputy issue on the **TCC** daemon when granting privileges to an app if there's another app with said bundle ID previously registered with `lsregister`, which will grant Full Disk Access permission to both applications
* `System Settings.app` incorrectly display the name of the chosen application via UI file picker
* `System Settings.app` will perform operations on any application(s) with a same bundle ID registered.
