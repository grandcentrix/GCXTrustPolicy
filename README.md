# GCXTrustPolicy
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![Release](https://img.shields.io/github/release/grandcentrix/GCXTrustPolicy.svg) [![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)


SSL pinning and trust validation framework for iOS.  💻  <- 👮 -> ☁️

Optimized for Swift and working from plain old Objective-C as well.

<br />

## Abstract

Users, developers and applications expect end-to-end security on their secure channels, but some secure channels are not meeting the expectation. Specifically, channels built using well known protocols such as VPN, SSL, and TLS can be vulnerable to a number of attacks. This is where SSL-validation come into play as it prevents from Man-in-The-Middle attacks and other vulnerabilities.
This framework is intended as customizable drop-in-solution that makes SSL-validation more comfortable and reliable secure.


<br />

## General

When a TLS certificate is verified, the operating system verifies its chain of trust. If that chain of trust contains only valid certificates and ends at a known (trusted) anchor certificate, then the certificate is considered valid. If it does not, it is considered invalid. When using a commercially signed certificate from a major vendor, the certificate should “just work”.
When using a self-signed certificate, connecting to a host by IP address (where the networking stack cannot determine the server’s host name) or providing service for multiple domains within a single certificate that is not trusted for those domains the certificate will not operate and you will have to do some extra work.

<br />

## Installation

If you encounter problems check our [troubleshooting section](#Troubleshooting) or file an Issue.

We will give our best trying to help you out. 🙂

#### Carthage

```ruby
github "grandcentrix/GCXTrustPolicy"
```

#### Carthage

Coming Soon!


#### Manual

- Start a new XCode Workspace.
- Create new App
- Import GCXTrustPolicy.xcodeproj into your Workspace
- Go to "Project Settings" -> "General Tab"
- Add `GCXTrustPolicy.framework` to the "Embedded Binaries" section
- Build and Run

<br />


## Example

#### Steps: 

* Add the certificate(s) to pin to your project
* Create a validation policy 
* Perform a URL request using a secure connection (such as https)
* URLSessionDelegate receives an authentication challenge
* Validate the policy against the remote trust


#### Simple example 


```swift
// create a policy for the host:
let policy = trustManager.create(type: .pinPublicKey, hostName: "pinnedHost.com")
    
// [--- perform network call urlSession(_:didReceive:completionHandler:) ---]

// In URLSessionDelegate or NSURLConnectionDelegate callbacks retrieve the remote trust on authentication challenge:
guard let serverTrust = challenge.protectionSpace.serverTrust else { /* handle case ... */ }

// Let the policy validate the given trust:
let isTrusted = pinningPolicy.validate(trust: serverTrust)

// Reject connection to suspicious servers
if isTrusted {
  // Success! Server trust has been established.
} else {
  // Fail! Non-trustable server!
}
    
```

#### Validation types

With GCXTrustPolicy offers multiple validation types:

- Pin a Certificate's Public Key
- Pin a Certificate
- Use a complete custom validation
- Use default validation of the operation system
- Disable validation for a given host

#### Detailed examples

For more examples please refer to [Examples](Examples.md)

<br />

## Documentation

Please see source code documentation in [TrustPolicy.swift](TrustPolicy.swift) for further information.

<br />

## Troubleshooting

* If you running an Objective-C project and encounter  an  `dyld: Library not loaded: @rpath/libswiftCore.dylib` error try to
set the Xcode build option 'Embedded Content Contains Swift Code' to 'YES'.

<br />

## Further reference

Apple developer documentation covering enhanced trust authentication: 
[Performing Manual Server Trust Authentication](https://developer.apple.com/documentation/foundation/url_loading_system/handling_an_authentication_challenge/performing_manual_server_trust_authentication)

The following OWASP page gives an detailed overview about [Transport Layer Protection](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet) and the whole process of [Pinning](https://www.owasp.org/index.php/Pinning_Cheat_Sheet) at a glance.

The following informative blog post provides some information on which keys to pin and what the trade-offs are: https://noncombatant.org/2015/05/01/about-http-public-key-pinning/.

<br />

## Credits

The underlying code is based on the suggestions and implementation strategies of OWASP's chapter on [Certificate and Public Key Pinning](https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning). Unit Test approaches in Swift are inspired from the well-known [Alamofire](https://github.com/Alamofire/Alamofire) and [TrustKit](https://github.com/datatheorem/TrustKit).

<br />

## License

```
Copyright 2017 grandcentrix GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

<br />