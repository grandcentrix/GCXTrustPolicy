# GCXTrustPolicy
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![Release](https://img.shields.io/github/release/grandcentrix/GCXTrustPolicy.svg) [![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)

SSL pinning and trust validation framework for iOS


## Abstract

Users, developers and applications expect end-to-end security on their secure channels, but some secure channels are not meeting the expectation. Specifically, channels built using well known protocols such as VPN, SSL, and TLS can be vulnerable to a number of attacks. This is where SSL-validation come into play as it prevents from Man-in-The-Middle attacks and other vulnerabilities.
This framework is intended as customizable drop-in-solution that makes SSL-validation more comfortable and reliable secure.

It helpes, decouple the release cycle from the certificate validity.


## General

When a TLS certificate is verified, the operating system verifies its chain of trust. If that chain of trust contains only valid certificates and ends at a known (trusted) anchor certificate, then the certificate is considered valid. If it does not, it is considered invalid. When using a commercially signed certificate from a major vendor, the certificate should “just work”.
When using a self-signed certificate, connecting to a host by IP address (where the networking stack cannot determine the server’s hostname) or providing service for multiple domains with a single certificate that is not trusted for those domains the certificate will not operate and you will have to do some extra work.
<br />

## Installation

#### Carthage

```ruby
github "grandcentrix/GCXTrustPolicy"
```

Make sure you have Apple's `Xcode Commandline Tools` installed. This allows Module `CommonCrypto` to reference the Umbrella Header at `/usr/include/CommonCrypto/`


#### Manual

- Start new XCode Workspace.
- Create new App
- Import GCXTrustPolicy.xcodeproj into Workspace
- Go to Project Settings -> General Tab
-- Add GCXTrustPolicy.framework in the Embedded Binaries
- Build and Run


## Usage

Depending on your needs you can either provide a custom validation (by using the `CustomValidation` closure) according to [Apple Developer: Overriding SSL-Chain Validation](https://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/NetworkingTopics/Articles/OverridingSSLChainValidationCorrectly.html). It is also possible to only rely on pinning by skipping the certificate chain validation process by setting `allowInsecureServerTrust = true`. A third option is to pin again a trusted Server, which provides the valid certificates for a given domain.

If you want to use Pinning do not forget to add the certificates into your Project. If you want to use a different bundle than the main NSBundle (default setting) you will have to advice the `ComposePolicy` to use it.

1. Define a host and a `ValidationType` to evaluate
2. Create the `TrustPolicy` using the `ComposePolicy` abstraction class
3. Use the `TrustManager` to manage multiple trust policies
4. Use the `-validate(withTrust: SecTrust)` of the `TrustPolicy` to evaluate authentication challenges


## Hands-On
### Host name

The provided host name must match either the leaf certificate’s Common Name or one of the names in its Subject Alternate Name extension.

### Validation types

- `standard`: Perform a standard validation. Using the system provided standard mechanism that is basically a X.509 certificate trust evaluation in a recursive two-step process down to the trusted anchor certificate.

- `pinPublicKey`: Public key pinning: Uses the pinned public keys to validate the server trust. The server trust is considered valid if one of the pinned public keys match one of the server certificate public keys. A default host validation like in 'DefaultValidation' is also done. Note: Applications that use public key pinning usually don't need an app update if the server renews it's certificate(s) as the underlying public key remains valid.

- `pinCertificate`: Certificate pinning: Uses the pinned certificates to validate the server trust. The server trust is considered valid if one of the pinned certificates match one of the server certificates. A default host validation like in 'DefaultValidation' is also done. A drawback is that if the server renews it's certificate(s) a new app with new certificate has to be shipped as the old one bundeled with the app is no longer valid.

- `pinPublicKeyOnline`: Public key pinning with a Trusted Server: Uses the provided TrustServer and TrustServerCertificate to recieve a signed file from the Server. The server trust is considered valid if one of the pinned public keys match one of the server certificate public keys. A default host validation like in 'DefaultValidation' is also done. Note: Applications that use public key pinning usually don't need an app update if the server renews it's certificate(s) as the underlying public key remains valid.

- `pinCertificateOnline`: Certificate pinning with a Trusted Server: Uses the provided TrustServer and TrustServerCertificate to recieve a signed file from the Server. With this file the certificate is validated. A default host validation like in 'DefaultValidation' is also done.

- `disabled`: No validation at all. This will always consider any server trust as valid.

- `custom`: Perform a complete custom validation using a closure.


### TrustPolicyType enumeration

###### Swift

```swift
public enum ValidationType: Int {
    case disabled = 0
    case standard
    case custom
    case pinCertificate
    case pinPublicKey
    case pinCertificateOnline
    case pinPublicKeyOnline
}
```


###### Objective-C

```objective-c
typedef SWIFT_ENUM_NAMED(NSInteger, GCXValidationType, "ValidationType") {
  GCXValidationTypeDisabled = 0,
  GCXValidationTypeStandard = 1,
  GCXValidationTypeCustom = 2,
  GCXValidationTypePinCertificate = 3,
  GCXValidationTypePinPublicKey = 4,
  GCXValidationTypePinCertificateOnline = 5,
  GCXValidationTypePinPublicKeyOnline = 6,
};
```


###  Setup example

##### Preparations: 

* add certificates to pin to your project
* create the policy
* add the policy to the TrustManager
* on authentication challenge, validate the trust against the policy

###### Simple setup: 


```swift
let exampleHost = "https://www.the-host-to-pin.com"
    
// create a policy
let pinningPolicy = ComposePolicy(withValidation: .pinPublicKey, forHost: exampleHost).create()
    
// use add(policy:) for adding a singe policy
TrustManager.sharedInstance.add(policy: pinningPolicy)
    
```

###### Simple validation: 

```swift
if let policy = TrustManager.sharedInstance.policy(forHost: challengedHost) {
   if policy.validate(with: trust) {
        // Success! Server trust has been established.
   } else {
        // Failed validation! Not secure to connect!!!
   }
    
```

###### Setup of multiple policies (Swift):

```swift

func setupTrustPolicies() {

    // - .standard: - //
    // compose and build a default validation policy
    let exampleHost = "https://www.the-host-to-pin.com"
    let defaultPolicy = ComposePolicy(withValidation: .standard, forHost: exampleHost).create()

    // - .pinPublicKey: - //
    // compose and build a public key pinning policy
    let pinningHost = URL(string:PINNING_HOST_URL_STRING)!.host!
    let composer = ComposePolicy(withValidation: .pinPublicKey, forHost: pinningHost)
    let pinningPolicy = composer.create()

    // - .pinPublicKeyOnline: - //
    // compose and build a public key pinning with trustServer policy
    let grandcentrix = URL(string: "https://www.grandcentrix.net")!.host!
    let pkOnline = ComposePolicy(withValidation: .pinPublicKeyOnline, forHost: grandcentrix)

    // set Trust Anchor
    pkOnline.trustServer = URL(string: "https://pinning.gcxi.de/gcx.json.signed")
    pkOnline.trustServerCertificate = Data(base64Encoded: "MIIFIDCCAwgCCQCFB0NhqrdqPDANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJERTEMMAoGA1UECAwDTlJXMRAwDgYDVQQHDAdDb2xvZ25lMRUwEwYDVQQKDAxncmFuZGNlbnRyaXgxDDAKBgNVBAMMA2djeDAeFw0xNzAzMDgxNTI3MDhaFw0zNzAzMDMxNTI3MDhaMFIxCzAJBgNVBAYTAkRFMQwwCgYDVQQIDANOUlcxEDAOBgNVBAcMB0NvbG9nbmUxFTATBgNVBAoMDGdyYW5kY2VudHJpeDEMMAoGA1UEAwwDZ2N4MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwmridNgOSL5qtU2VOVCtMg0cYonTl7KKH8QAU3DOF9bHUo/R5w5cwaNV7ICdfliknjV+6s83qqzj2hDucDuoxftaa02BxoSXl3zZ9rwzmsrLeD4n91V7m5FA2T9NrRojuIy1vcuYTn6DkSdEeRfyOGob4nYbtPGYQKQXYcwTTCm9TC16CYAmOIAEVDPXsl6nZXV2iH0N70tM1qc5qIYjZRdnR5Ig+oR8X+dyWo+vJMfaOwza8c/LlTZFhaJ1L7hK7QdcHlm6Gqx7iq5FePZSCyMdrcuTE2IJFFiCDN38sL3qezoVFDs/9YC09CM5AxVQDehd0t/30BtyrcqzXgdshIFlqwUv3i9Til2GW23vwkZik5q72zuxH/uG4XYwMhdl3MtHrypa99+o8nEt+iHN6LZ9T1dhs3xgihkvEZ1T7S95/Lg2Ek1EFyzgAyQtJa4x27q6epH+15lEMcuAB/f3e+AgRRbImKhGWVuqxu1xIbga5e0ZlY1/f0rxFmb0r55Zdl0ssZIjSpxT+wTsRchUr5DQlvX8OGFcO+gsLWlhlOFduVgHsllM0NnHu6tEdvCLj42Qcbcy+02upxnhDnItWXu9ZLUgVf23etpk2VNxv6AB59bspX+k9pTqVIxuvzyfnVqPrmzGt16RRYdlQ91vGs9ig1+rT1u8wP5MJe6bzxMCAwEAATANBgkqhkiG9w0BAQ0FAAOCAgEAf5J1V1YUPJffVhh/tXJWUkIjV8bj/a8aScjSINJIn0scomRrvTfHXrHw6dqws1ly3MunubrfISVc9ZIqUMW+zBMNK+EqEYqbsvVUSW/O327KkqxgH9evDb6+Cw10I4iA0GRJ+vp8ON/qD0bZAZN1b/4O9xdRR/aXAov9SiYaY+CRWrxqmTw4MY45Qzmo2S51wf4L+s59suFIE2zm+xU9OddptApxbkj4YRPB0jcosBWRqYZWKzUP8/qBYIXNolLkl42UbPcFnVLNDxAMLx8J8WWBHomjxoHkjD9/R6OCgeHNP49Nh9qeUtbLPcDx5bw/L2QiXi63+EO08nBs7dy/XPNRn+iNBsYA5bNtRSulw6TgatrwIv1flDBaFPR/2l91SpNEXvKCipkzCHK9XjHBzbZBhbHInGKMEz9WIYgbw1P60kV8U9zKwaWgjuN7g1QMmIpxqIaC64rY8ArBJyrhmKR1OHyRd/k2e6kigqyTzLt/1VZh8KaSzgmoHe/jqV8zyrK4wCvts3MCR/XDI2IVZPBx4iFlJ+CrD4kWslY0KjbpRS96stcVKQsEyFx1RbafINSH3OzHA3dDJ8wToYzyit6Fs9bzmqtIencYYxyrGQatJq8fUDIRXyNgqIZtFzWH4zruvi3ol8v0X/0W4Rjl1cEztWUvUzS2bmJxizen+tE=")
    pkOnline.customer = "gcx"

    let pkOnlinePolicy = pkOnline.create()

    // add the three policies to the manager class at once
    TrustManager.sharedInstance.add(policies: [defaultPolicy, pinningPolicy, pkOnlinePolicy])
}
```

###### Setup of multiple policies (Objective-C)

```objective-c

- (void)setupTrustPolicies {

    // - .standard: - //
    // compose and build a default validation policy
    NSString *exampleHost = "https://www.the-host-to-pin.com";
    id<GCXTrustPolicy> defaultPolicy = [[[GCXComposePolicy alloc] initWithValidation:GCXValidationTypeStandard forHost:exampleHost] create];

    // - .pinPublicKey: - //
    // compose and build a public key pinning policy
    NSString *pinningHost = [NSURL URLWithString:PINNING_HOST_URL_STRING].host;
    GCXComposePolicy *composer = [[GCXComposePolicy alloc] initWithValidation:GCXValidationTypePinPublicKey forHost:pinningHost];
    id<GCXTrustPolicy> pinningPolicy = [composer create];

    // - .pinPublicKeyOnline: - //
    // compose and build a public key with TrustServer pinning policy
    NSString *grandcentrix = [NSURL URLWithString:@"https://www.grandcentrix.net"].host;
    GCXComposePolicy *pkOnline = [[GCXComposePolicy alloc] initWithValidation:GCXValidationTypePinPublicKeyOnline forHost:pinningHost];

    // set Trust Anchor
    pkOnline.trustServer = [NSURL URLWithString:@"https://pinning.gcxi.de/gcx.json.signed"]
    pkOnline.trustServerCertificate = [NSData dataFromBase64String: @"MIIFIDCCAwgCCQCFB0NhqrdqPDANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJERTEMMAoGA1UECAwDTlJXMRAwDgYDVQQHDAdDb2xvZ25lMRUwEwYDVQQKDAxncmFuZGNlbnRyaXgxDDAKBgNVBAMMA2djeDAeFw0xNzAzMDgxNTI3MDhaFw0zNzAzMDMxNTI3MDhaMFIxCzAJBgNVBAYTAkRFMQwwCgYDVQQIDANOUlcxEDAOBgNVBAcMB0NvbG9nbmUxFTATBgNVBAoMDGdyYW5kY2VudHJpeDEMMAoGA1UEAwwDZ2N4MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwmridNgOSL5qtU2VOVCtMg0cYonTl7KKH8QAU3DOF9bHUo/R5w5cwaNV7ICdfliknjV+6s83qqzj2hDucDuoxftaa02BxoSXl3zZ9rwzmsrLeD4n91V7m5FA2T9NrRojuIy1vcuYTn6DkSdEeRfyOGob4nYbtPGYQKQXYcwTTCm9TC16CYAmOIAEVDPXsl6nZXV2iH0N70tM1qc5qIYjZRdnR5Ig+oR8X+dyWo+vJMfaOwza8c/LlTZFhaJ1L7hK7QdcHlm6Gqx7iq5FePZSCyMdrcuTE2IJFFiCDN38sL3qezoVFDs/9YC09CM5AxVQDehd0t/30BtyrcqzXgdshIFlqwUv3i9Til2GW23vwkZik5q72zuxH/uG4XYwMhdl3MtHrypa99+o8nEt+iHN6LZ9T1dhs3xgihkvEZ1T7S95/Lg2Ek1EFyzgAyQtJa4x27q6epH+15lEMcuAB/f3e+AgRRbImKhGWVuqxu1xIbga5e0ZlY1/f0rxFmb0r55Zdl0ssZIjSpxT+wTsRchUr5DQlvX8OGFcO+gsLWlhlOFduVgHsllM0NnHu6tEdvCLj42Qcbcy+02upxnhDnItWXu9ZLUgVf23etpk2VNxv6AB59bspX+k9pTqVIxuvzyfnVqPrmzGt16RRYdlQ91vGs9ig1+rT1u8wP5MJe6bzxMCAwEAATANBgkqhkiG9w0BAQ0FAAOCAgEAf5J1V1YUPJffVhh/tXJWUkIjV8bj/a8aScjSINJIn0scomRrvTfHXrHw6dqws1ly3MunubrfISVc9ZIqUMW+zBMNK+EqEYqbsvVUSW/O327KkqxgH9evDb6+Cw10I4iA0GRJ+vp8ON/qD0bZAZN1b/4O9xdRR/aXAov9SiYaY+CRWrxqmTw4MY45Qzmo2S51wf4L+s59suFIE2zm+xU9OddptApxbkj4YRPB0jcosBWRqYZWKzUP8/qBYIXNolLkl42UbPcFnVLNDxAMLx8J8WWBHomjxoHkjD9/R6OCgeHNP49Nh9qeUtbLPcDx5bw/L2QiXi63+EO08nBs7dy/XPNRn+iNBsYA5bNtRSulw6TgatrwIv1flDBaFPR/2l91SpNEXvKCipkzCHK9XjHBzbZBhbHInGKMEz9WIYgbw1P60kV8U9zKwaWgjuN7g1QMmIpxqIaC64rY8ArBJyrhmKR1OHyRd/k2e6kigqyTzLt/1VZh8KaSzgmoHe/jqV8zyrK4wCvts3MCR/XDI2IVZPBx4iFlJ+CrD4kWslY0KjbpRS96stcVKQsEyFx1RbafINSH3OzHA3dDJ8wToYzyit6Fs9bzmqtIencYYxyrGQatJq8fUDIRXyNgqIZtFzWH4zruvi3ol8v0X/0W4Rjl1cEztWUvUzS2bmJxizen+tE="]
    pkOnline.customer = @"gcx"

    id<GCXTrustPolicy> pkOnlinePolicy = [pkOnline create];


    // add the three policies to the manager class at once
    GCXTrustManager *manager = [GCXTrustManager sharedInstance];
    [manager addWithPolicies:@[defaultPolicy, pinningPolicy, pkOnlinePolicy]];
}
```


### Validation example

###### Swift

Perform the policy validation in your URLSessionDelegate callback in response to an authentication request:
You can also use NSURLConnection to authenticate.
```swift
extension ViewController: URLSessionDelegate {
   // Of course it is also possible to use NSURLConnection here...
   func urlSession(_ session: URLSession, 
        didReceive challenge: URLAuthenticationChallenge, 
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
       let challengedHost = challenge.protectionSpace.host
        
       // Validate the remote trust
       if let trust = challenge.protectionSpace.serverTrust {
           var isTrusted = false
            
           // Retrieve a matching policy for the challenged host
           
           if let policy = TrustManager.sharedInstance.policy(forHost: challengedHost) {
               isTrusted = policy.validate(with: trust)
                
               if isTrusted {
                   // Success! Server trust has been established.
                   let credential = URLCredential(trust: trust)
                   completionHandler(.useCredential, credential);
                   return
               }
           }
            
           // Cancel the challenge
           completionHandler(.cancelAuthenticationChallenge, nil)
       }
   }

```


###### Objective-C

Perform the policy validation in your URLSessionDelegate callback in response to an authentication request:
You can also use NSURLConnection to authenticate.

```objective-c
// Of course it is also possible to use NSURLConnection here...
-(void)URLSession:(NSURLSession *)session 
       didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge 
       completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler
{
    NSString *challengedHost = challenge.protectionSpace.host;
    NSString *authorizationMethod = challenge.protectionSpace.authenticationMethod;
    
    // Validate the remote trust
    if([authorizationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        BOOL isTrusted = false;
        SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
        
        // Retrieve a matching policy for the challenged host
        id <GCXTrustPolicy> policy = [[GCXTrustManager sharedInstance] policyForHost:challengedHost];
        
        // Validate the server trust
        isTrusted = [policy validateWith:serverTrust];
        if (isTrusted) {
            // Success! Server trust has been established.
            NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
            completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
            return;
        }
    }
    
    // Cancel the challenge
    completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
}
```


### Examples on validation customization:


###### Swift

```swift
// construct the TrustPolicyComposer
let type: ValidationType = /* a type */
let exampleHost: String =  /* a host */
let composer = ComposePolicy(withValidation: type, forHost: exampleHost)
        
// default setting, checks host name too when performing certificate chain validation
// must match either the leaf certificate’s Common Name or one of the names in its Subject Alternate Name extension
composer.validateHostName = true

// default setting, uses all certificates from the specified bundle
// assign a custom bundle if needed
composer.certificateBundle = Bundle.main

// default setting, self-signed and invalid certificates are assumed as insecure
// when `true` no hostname and no certificate chain validation is performed
composer.allowInsecureServerTrust = false;

// Custom validation closure, has to be assigned when performing
// a custom validation of type .CustomValidation
composer.customValidation = {(trust: SecTrust?) -> Bool in
    let isTrusted = /* perform your custom validation ... */
    return isTrusted
}
```


###### Objective-C

```objective-c
// construct the TrustPolicyComposer
TrustPolicyType type = /* a type */
NSString *exampleHost =  /* a host */
GCXComposePolicy *composer = [[GCXComposePolicy alloc] initWithValidation:type forHost:exampleHost];
  
// default setting, checks host name too when performing certificate chain validation
// must match either the leaf certificate’s Common Name or one of the names in its Subject Alternate Name extension
composer.validateHostName = YES;

// default setting, uses all certificates from the specified bundle
// assign a custom bundle if needed
composer.certificateBundle = [NSBundle mainBundle];

// default setting, self-signed and invalid certificates are assumed as insecure
// when `true` no hostname and no certificate chain validation is performed
composer.allowInsecureServerTrust = NO;

// Custom validation closure, has to be assigned when performing
// a custom validation of type .CustomValidation
composer.customValidation = ^BOOL(SecTrustRef _Null_unspecified trust) {
    BOOL isTrusted = /* perform your custom validation ... */
    return isTrusted;
}
```

## Online trust server

#### Grandcentrix

To verify the trust with an online server you can use the grandcentrix.net server. Contact us at hello@grandcentrix.net.

#### Selfhosted

see the bin/ directory for further information. This Script needs to run every 5 Minutes, so it generates a fresh copy of the signed json. It will output the pinning certificate the first time it is used. 

## Documentation

Please see the soure code for further informations.


## Further reference

The following OWASP page gives an detailed overview about [Transport Layer Protection] (https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet) and the whole process of [Pinning](https://www.owasp.org/index.php/Pinning_Cheat_Sheet) at a glance.

The following informative blog post provides some information on which keys to pin and what the trade-offs are: https://noncombatant.org/2015/05/01/about-http-public-key-pinning/.


## Credits

The underlying code is based on the suggestions and implementation strategies of OWASP's chapter on [Certificate and Public Key Pinning](https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning). Unit Test approaches in Swift are inspired from the well-known [Alamofire](https://github.com/Alamofire/Alamofire) and [TrustKit](https://github.com/datatheorem/TrustKit).


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
