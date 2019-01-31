# Examples

#### General steps: 

* Add the certificate(s) to pin to your project
* Create a validation policy 
* Perform a URL request using a secure connection (such as https)
* URLSessionDelegate receives an authentication challenge
* Validate the policy against the remote trust


#### Validation types

```swift
public enum ValidationType: Int {
    case disabled = 0
    case standard
    case custom
    case pinCertificate
    case pinPublicKey
}
```

#### Create policies example

```swift
// Create a simple policy:
let pinPolicy = trustManager.create(type: .pinPublicKey, hostName: "pinnedHost.com")

// Create a customised policy:
let settings = ValidationSettings.defaultSettings
settings.sslValidateHostName = false
let noHostCheckPolicy = trustManager.create(type: .pinPublicKey, hostName: "otherPinnedHost.com", settings: settings)

// Add policies to trust manager:
trustManager.add(policies: [pinPolicy, noHostCheckPolicy]])
```

#### Validation example

Perform the policy validation in URLSessionDelegate or NSURLConnectionDelegate  callback in response to an authentication request:

```swift
extension ViewController: URLSessionDelegate {

   func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
       let challengedHost = challenge.protectionSpace.host
        
       // Validate remote trust
       if let serverTrust = challenge.protectionSpace.serverTrust {
           var isTrusted = false
            
           // Retrieve a matching policy for the challenged host
           if let policy = TrustManager.shared.policy(for: challengedHost) {
               isTrusted = policy.validate(trust: serverTrust)
                
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

<br />

## Further usage advise

### Validation types

- disabled: 
Performs no validation at all. It is advised to be careful with disabling validation because *any* server trust will always be considerd as valid.

- standard:
Performs the system standard X.509 trust validation that involves server identity checks to ensure talking to the correct server.

- custom:
Perform a completely custom trust validation. Handling the validation process is completely up to the developer.

- pinCertificate:
Perform a standard SSL validation *and* pins the trusted certificate(s).
The validation process is considered successful if one of the pinned public key(s) match one of the servers public key(s) and standard X.509 trust validation has also been successful.

- pinPublicKey:
Perform a standard SSL validation and pins the trusted certificate(s) public key(s).
The validation process is considered successful if one of the pinned
public key(s) match one of the servers public key(s) and standard X.509 trust validation has also been successful.

<br />

#### Custom validation

Depending on your needs you can provide a custom validation by using the `CustomValidationClosure` closure. For implementation approaches please 
refer to [Apple Developer: Overriding SSL-Chain Validation](https://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/NetworkingTopics/Articles/OverridingSSLChainValidationCorrectly.html). 

<br />

#### Pinning

Is possible, but not advised, to rely only on pinning by skipping the default SSL certificate chain validation. Assign `certificatePinOnly = true` in `ValidationSettings` object. Unsecure, but useful when performing validation with servers that utilize self-signed or expired certificates.
When using Pinning the corresponding certificates have to be added to the Project. During validation check all necessary informations (e.g. Public Key) will be extracted. If you want to use a different bundle than the main Bundle (e.g. for updatability of certificates) you can use `ValidationSettings.

<br />

### Host name

The provided host name must match either the leaf certificate’s Common Name or one of the names in its Subject Alternate Name extension.

<br />

### Multiple trust policies

Use the `TrustManager` to manage multiple trust policies

<br />

### Validation types

- disabled: 
Performs no validation at all. It is advised to be careful with disabling validation because *any* server trust will always be considerd as valid.

- standard:
Performs the system standard X.509 trust validation that involves server identity checks to ensure talking to the correct server.

- custom:
Perform a completely custom trust validation. Handling the validation process is completely up to the developer.

- pinCertificate:
Perform a standard SSL validation *and* pins the trusted certificate(s).
The validation process is considered successful if one of the pinned public key(s) match one of the servers public key(s) and standard X.509 trust validation has also been successful.

- pinPublicKey:
Perform a standard SSL validation and pins the trusted certificate(s) public key(s).
The validation process is considered successful if one of the pinned
public key(s) match one of the servers public key(s) and standard X.509 trust validation has also been successful.

<br />
