# Disclaimer

This report was sent to Apple's bounty program on 5/23/25, and rejected on 6/23/25. Stackhopper is not responsible for misuse of this information, nor any damage performed by it. For educational purposes only.

# Summary

The **ShareKit** framework's **ShareSheetUI** plugin is vulnerable to an arbitrary file download from a remote host serving spoofed HTTP content and consequential rendering on a WebKit sandbox upon invoking `/System/Library/PrivateFrameworks/ShareKit.framework/Versions/A/PlugIns/ShareSheetUI.appex/Contents/MacOS/ShareSheetUI`, leading to untrusted code execution on Apple devices. This affects macOS 15.5 and below, and iOS 18.5 and below (evidence provided shows the exploit running on iOS 18.3).
# Explanation

Note: **Shortcuts.app** has been chosen for exploiting this vulnerability, but it can be triggered from any application using the `ShareKit` private framework. The amount of actions needed on a shortcut for triggering the attack are two: an input (it can be a text box, an input from Finder's contextual menu, etc) where the malicious website will be passed upon, and a Safari web view.

<img width="771" alt="Image" src="https://github.com/user-attachments/assets/3cc5edfe-ea0e-43da-b7b6-168fd03bb628" />

_Fig 1. Shortcut tasks structure_

Upon a Shortcuts application that, given an URL and after rendering a web view (via Safari) of a malicious webpage, a user will be given two options with visual cues (icons) once the shortcut successfully finishes: a **Quick Look** option and a **Share** option.

<img width="1024" alt="Image" src="https://github.com/user-attachments/assets/b588c284-d12e-467d-b16c-456b736c1385" />

_Fig 2. Safari web view needed to trigger the vulnerability_

<img width="100" alt="Image" src="https://github.com/user-attachments/assets/6741d0ea-ef85-49ae-a15f-6fd80155b758" />

_Fig 3. Vulnerable action (Share button)_

There is a vulnerability on the 'Share' button located at the Safari Web View's output modal section of this shortchut, which is handled by `/System/Library/PrivateFrameworks/ShareKit.framework/Versions/A/PlugIns/ShareSheetUI.appex/Contents/MacOS/ShareSheetUI`.  Upon clicking on it, will try to load the malicious website and its `favicon.ico` again (outside of the Web View rending task) and two resources remotely, that should be bundled in the UI kit library for Shortcuts instead of looking them up on a remote host:

* `apple-touch-icon.png`
* `apple-touch-icon-precomposed.png`
* `apple-touch-icon-120x120.png` 
* `apple-touch-icon-120x120-precomposed.png` 

A malicious remote server can serve files with these names but with different kinds of content, and said content will be rendered on a sandboxed WebKit container without any user interaction or TCC permissions prompting.

The reason this happens is because the HTTP requests issued by `com.apple.WorkflowKit.ShortcutsViewService` framework which are processed by `com.apple.WebKit.Networking` accept any type of content due to lack of `Content-Type` header validation and to a lesser extent, the value `*/*` on the `Accept` header. Attached is an example communication with a Burp Suite Collaborator domain.

<img width="1158" alt="Image" src="https://github.com/user-attachments/assets/f05bd69c-6adb-4485-947e-7f60ad9b0ee8" />
<img width="1157" alt="Image" src="https://github.com/user-attachments/assets/f15085c2-13e2-43ec-a98c-1ea8ebb568c9" />

_Fig 4-5. Insecure HTTP header configuration leading to HTTP content spoofing_

Moreover, a folder with one of the aforementioned names can be created, and a `301` HTTP code will be issued after a `GET` request is requested, thus redirecting to an `index.html` within that folder.

<img width="1891" alt="Image" src="https://github.com/user-attachments/assets/ae974b95-4ef1-4986-870f-cf29f10e1a16" />

_Fig 6. HTTP content spoofing alternative using a folder and HTTP redirects_

# Impact

This report consists of three vulnerabilities chained together:

* An , arbitrary content rendering on the device
* Remote HTTP content spoofing enabled by insecure HTTP content handling on HTTP requests created by `com.apple.WebKit.Networking` and the `CFNetwork` private framework
* An out-of-band web content download, rendering on a WebKit container (tied to a Safari web view) linked to the Shortcuts `Share` button

The main impact of this vulnerability lies in

* Downloading and storing an arbitrary file to the device's storage unit
* Executing untrusted remote and local code execution on a sandboxed WebKit container from a remote origin, with no visual indicators of the execution

This vulnerability can be easily employed in an exploit chain to deliver WebKit and Safari sandbox escape and RCE vulnerabilities with multiple technologies (JavaScript or WebASM, for example) as it needs minimal user interaction and will render the untrusted code. 

## Reproduction from the `lldb` debugger

1. Run `lldb -- /System/Applications/Shortcuts.app/Content/MacOS/Shortcuts`
2. Set up breakpoints to debug right before the HTTP requests are issued
	1. `b '-[EXConcreteExtension _reallyBeginExtensionRequest:synchronously:completion:]'`
	2. `b 'objc?msgSend$_urlItems'`
  3. `b ShareKit-[SHKSharingServicePicker _requestHeaderMetadataWithURLRequests:completionHandler:]`
3. Run the process with `run` and analyze as needed.

Some other useful breakpoints are as follow.

```
b -[_EXNSExtensionContextShimImplementation openURL:completionHandler:]
b -[EXConcreteExtension beginExtensionRequestWithOptions:inputItems:completion:]
b -[EXConcreteExtension beginExtensionRequestWithOptions:inputItems:listenerEndpoint:error:]
b -[EXConcreteExtension _completeRequestReturningItems:forExtensionContextWithUUID:completion:]
b -[EXConcreteExtension beginExtensionRequestWithInputItems:listenerEndpoint:completion:]
b -[EXConcreteExtension beginExtensionRequestWithInputItems:listenerEndpoint:error:]
b -[EXConcreteExtension beginExtensionRequestWithInputItems:completion:]
b -[EXConcreteExtension beginExtensionRequestWithInputItems:error:]
```

# Proof of Concept

Proof of concept videos available ([macOS](https://youtu.be/EL88E7tzApQ) and [iOS](https://youtube.com/shorts/wksDhdHEgEQ)).
