# Summary

macOS Tahoe 26 and lower are vulnerable to a local Denial of Service vulnerability on the ViewBridge XPC service targeting the `LocalAuthentication` private framework. This was partially fixed in CVE-2025-24199, but the Denial of Service can be scoped to the LocalAuthentication private framework.

# Explanation

The vulnerability is triggered when the `AppleLanguages` global variable, which takes arrays as inputs, is set with the syntax that would be used for a string-based variable. The correct way to set this variable is

`defaults write -g AppleLanguages '("en_US")'`

while the vulnerable way abused non-printable characters and the built-in Bash/Zsh `eval()` function

`$(echo "defaults write -g AppleLanguages '("en_US")'")`

After setting the global variable to any value (`%x` was used to attempt memory leaks but did not work) and upon debugging a process using the `LocalAuthentication` private framework such as `System Settings.app`, the behavior detected is that the function  `+[NSRemoteViewController requestViewController:connectionHandler:]` on `/System/Library/PrivateFrameworks/ViewBridge.framework/Versions/A/ViewBridge` (part of the `com.apple.ViewBridge` bundle) is failing as it does not receive a `NSString` object for its selector instance. This leads to a segmentation fault caused by a null pointer dereference. 

```
SecurityPrivacyExtension: (LocalAuthenticationUI) [com.apple.LocalAuthentication:RemotePasswordField] <private> did terminate with error:Error Domain=com.apple.ViewBridge Code=17 UserInfo={com.apple.ViewBridge.error.hint=connection to view service became invalid -- benign unless unexpected, com.apple.ViewBridge.error.description=NSViewBridgeErrorDisconnection}
```

It should be noted that the LocalAuthentication fails gracefully but ultimately does not allow for the desired change to take effect.

# Impact

This bug renders the `LocalAuthentication` private framework unable to perform authentication and authorization for any change requiring administrative (root) access; this would have repercussions across other Apple security mechanisms using said private framework. 

# Steps to reproduce

1. From the Terminal, change the AppleLanguages global variables with the following payload:

`$(echo "defaults write -g AppleLanguages '("en_US")'")`

2. Open `System Settings.app`or any app that invokes the `LocalAuthentication` framework.

3. The payload will be executed.


# Expected behavior

Under normal circumstances, the `LocalAuthentication` framework GUI should behave normally and allow for the root user's password to perform needed changes.

# Actual behavior

The `LocalAuthentication` framework fails and exits, not allowing the user to perform the required change after the authentication prompt.

# Proof of Concept

/evidence of the Denial of Service targeting the LocalAuthentication framework's authorization prompt for privileged access-based changes can be seen [here](https://youtu.be/u1hATKAYsq0).
