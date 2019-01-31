

# Examples

## Usage

Depending on your needs you can either provide a custom validation (by using the `CustomValidation` closure) according to [Apple Developer: Overriding SSL-Chain Validation](https://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/NetworkingTopics/Articles/OverridingSSLChainValidationCorrectly.html). It is also possible to only rely on pinning by skipping the certificate chain validation process by setting `allowInsecureServerTrust = true`. A third option is to pin again a trusted Server, which provides the valid certificates for a given domain.

If you want to use Pinning do not forget to add the certificates into your Project. If you want to use a different bundle than the main NSBundle (default setting) you will have to advice the `ComposePolicy` to use it.

1. Define a host and a `ValidationType` to evaluate
2. Create the `TrustPolicy` using the `ComposePolicy` abstraction class
3. Use the `TrustManager` to manage multiple trust policies
4. Use the `-validate(withTrust: SecTrust)` of the `TrustPolicy` to evaluate authentication challenges

<br />

## Hands-On
### Host name

The provided host name must match either the leaf certificate’s Common Name or one of the names in its Subject Alternate Name extension.

### Validation types

- `standard`: Perform a standard validation. Using the system provided standard mechanism that is basically a X.509 certificate trust evaluation in a recursive two-step process down to the trusted anchor certificate.

- `pinPublicKey`: Public key pinning: Uses the pinned public keys to validate the server trust. The server trust is considered valid if one of the pinned public keys match one of the server certificate public keys. A default host validation like in 'DefaultValidation' is also done. Note: Applications that use public key pinning usually don't need an app update if the server renews it's certificate(s) as the underlying public key remains valid.

- `pinCertificate`: Certificate pinning: Uses the pinned certificates to validate the server trust. The server trust is considered valid if one of the pinned certificates match one of the server certificates. A default host validation like in 'DefaultValidation' is also done. A drawback is that if the server renews it's certificate(s) a new app with new certificate has to be shipped as the old one bundeled with the app is no longer valid.

- `disabled`: No validation at all. This will always consider any server trust as valid.

- `custom`: Perform a complete custom validation using a closure.


### TrustPolicyType enumeration

#### Swift

```swift
public enum ValidationType: Int {
    case disabled = 0
    case standard
    case custom
    case pinCertificate
    case pinPublicKey
}
```


#### Objective-C

```objective-c
typedef SWIFT_ENUM_NAMED(NSInteger, GCXValidationType, "ValidationType") {
  GCXValidationTypeDisabled = 0,
  GCXValidationTypeStandard = 1,
  GCXValidationTypeCustom = 2,
  GCXValidationTypePinCertificate = 3,
  GCXValidationTypePinPublicKey = 4
};
```


###  Setup example

#### Preparations: 

* add certificates to pin to your project
* create the policy
* add the policy to the TrustManager
* on authentication challenge, validate the trust against the policy

#### Simple setup: 


```swift
let exampleHost = "https://www.the-host-to-pin.com"
    
// create a policy
let pinningPolicy = ComposePolicy(withValidation: .pinPublicKey, forHost: exampleHost).create()
    
// use add(policy:) for adding a singe policy
TrustManager.shared.add(policy: pinningPolicy)
    
```

#### Simple validation: 

```swift
if let policy = TrustManager.shared.policy(forHost: challengedHost) {
   if policy.validate(with: trust) {
        // Success! Server trust has been established.
   } else {
        // Failed validation! Not secure to connect!!!
   }
    
```

#### Setup of multiple policies (Swift):

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

    // add the three policies to the manager class at once
    TrustManager.shared.add(policies: [defaultPolicy, pinningPolicy])
}
```

#### Setup of multiple policies (Objective-C)

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
    
    // add the three policies to the manager class at once
    GCXTrustManager *manager = [GCXTrustManager shared];
    [manager addWithPolicies:@[defaultPolicy, pinningPolicy]];
}
```


### Validation example

#### Swift

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
           
           if let policy = TrustManager.shared.policy(forHost: challengedHost) {
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


#### Objective-C

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
        BOOL isTrusted = NO;
        SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
        
        // Retrieve a matching policy for the challenged host
        id <GCXTrustPolicy> policy = [[GCXTrustManager shared] policyForHost:challengedHost];
        
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


#### Swift

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


##### Objective-C

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

<br />
