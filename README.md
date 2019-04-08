# GCXTrustPolicy
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![Release](https://img.shields.io/github/release/grandcentrix/GCXTrustPolicy.svg) [![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)  [![Cocoapods compatible](https://img.shields.io/cocoapods/v/GCXTrustPolicy.svg)](https://cocoapods.org/)


SSL-pinning and trust validation framework for iOS.  💻  <- 👮 -> ☁️

Optimized for Swift and working from plain old Objective-C as well.

<br />

## Abstract

Users, developers and applications expect end-to-end security on their secure channels, but some secure channels are not meeting the expectation. Specifically, channels built using well known protocols such as VPN, SSL and TLS can be vulnerable to a number of attacks. This is where SSL-validation come into play as it prevents from Man-in-The-Middle attacks and other vulnerabilities.
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

### Cocoapods

```ruby
use_frameworks!

pod 'GCXTrustPolicy'

```

#### Cocoa Pods

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

#### General Steps

* Add the certificate(s) to pin to your project
* Create a validation policy 
* Perform a URL request using a secure connection (such as https)
* URLSessionDelegate receives an authentication challenge
* Validate the policy against the remote trust


#### Simple example 

```swift
// create a policy for the host:
let policy = trustManager.create(type: .pinPublicKey, hostName: "pinnedHost.com")

// >>> perform URL request to remot host <<<

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

GCXTrustPolicy offers multiple validation types:

- Pin a Certificate's Public Key
- Pin a Certificate
- Use a complete custom validation
- Use default validation of the operation system
- Disable validation for a given host


#### Detailed examples

For detailed examples please refer to [Examples](Examples.md) or source code examples for Swift and ObjC in [Integration Tests](https://github.com/grandcentrix/GCXTrustPolicy/tree/feature/swift4x/GCXTrustPolicyTests/Integration%20Tests).

<br />

## Documentation

Please see source code documentation in [TrustPolicy.swift](GCXTrustPolicy/TrustPolicy.swift) for detailed information.

<br />

## Glossary

#### TLS
Transport Layer Security (TLS) is a cryptographic protocols designed to provide communications security over a computer network

#### SSL
Secure Sockets Layer (SSL) is a cryptographic protocol that is deprecated and has been replaced by TLS

#### Certificate
A certificate is a digital file that is usable for SSL or TLS. The certificate assists with authenticating and verifying the identity of a host or website. It also enables the encryption of the exchanged information.

#### X.509
A standard defining a Public Key Infrastructure (PKI) to verify that a public key belongs to the identity contained within the certificate.

<br />

## Troubleshooting

If running an Objective-C project and encounter `dyld: Library not loaded: @rpath/libswiftCore.dylib` error try to setting the Xcode build option 'Embedded Content Contains Swift Code' to 'YES'.

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

