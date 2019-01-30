//
//  TrustPolicy.swift
//  GCXTrustPolicy
//
//  Copyright 2017 grandcentrix GmbH
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

import Foundation

/// Type alias for a closre that provides custom validation
public typealias CustomValidationClosure = (SecTrust?) -> (Bool)

@objc(GCXValidationType)
/// Trust policy validation types.
///
/// - disabled: Performs no validation at all.
///				It is advised to be careful with disabling validation
///				because *any* server trust will always be considerd as valid.
///
/// - standard: Performs the system standard X.509 trust validation that involves
///             server identity checks to ensure talking to the correct server.
///
/// - custom:	Performx a completely custom trust validation.
///				Handling the validation process is completely up to the developer.
///
/// - pinCertificate: 	Perform a standard SSL validation *and* pins the trusted certificate(s).
///						The validation process is considered successful if one of the pinned
///						public key(s) match one of the servers public key(s) and standard
///						X.509 trust validation has also been successful.
///
/// - pinPublicKey:     Perform a standard SSL validation and pins the trusted certificate(s)
///                     public key(s).
///                     The validation process is considered successful if one of the pinned
///                     public key(s) match one of the servers public key(s) and standard
///                     X.509 trust validation has also been successful.
public enum ValidationType: Int {
    case disabled = 0
    case standard
    case custom
    case pinCertificate
    case pinPublicKey
}

@objc(GCXTrustPolicy)
/// Protocol definition for validating a policy against a remote trust
public protocol TrustPolicy {
    
    /// Name of the host
    var hostName: String! { get set }
    
    /// Validates a policy against a given trust
    func validate(trust: SecTrust) -> Bool
}

@objc(GCXValidationCustomizable)
/// Protocol defines an object containing validation settings
public protocol ValidationCustomizable {
    
    /// Define if the host name will be checked during SSL validation.
    ///
    /// Default value is TRUE.
    var sslValidateHostName: Bool { get set }
    
    /// The bundle where to search for certificates.
    /// These certificates have to be bundled with the app, e.g. Xcode project folder.
    ///
    /// Taken into account only for certificate required validation, e.g.
    /// `ValidationType`:`.pinPublicKey` and `.pinCertificate`.
    ///
    /// By default the main Bundle is used as location for certificates.
    var certificateBundle: Bundle { get set }
    
    /// Allows to skip SSL validation and take only SSL pinning into account.
    ///
    /// This will completely skip certificate chain validation and host name checks
    /// during standard X.509 validation.
    /// Unsecure, but useful when performing validation with servers that utilize
    /// self-signed or expired certificates.
    ///
    /// Taken into account only for certificate required validation, e.g.
    /// `ValidationType`:`.pinPublicKey` and `.pinCertificate`.
    ///
    /// Default value is FALSE.
    var certificatePinOnly: Bool { get set }
    
    /// A custom closure for validation with `ValidationType`: `.custom`.
    /// When using this, all validation logic has to be contained within the closure.
    ///
    /// SSL validation checks are not done when using custom validation
    /// that has completey to be handled by the caller.
    ///
    /// By default the value is `nil`.
    var customValidation: CustomValidationClosure? { get set }
}

@objc(GCXTrustManaging)
/// Trusting protocol describing trust policiy management
public protocol TrustManaging {
    
    /// Dictionary of `TrustPolicy`s.
    /// It's suggested to use the host's name as key.
    var policies: [String: TrustPolicy] { get set }
    
    /// Retrieve all policy names.
    var allNames: [String] { get }
    
    /// Retrieve all `TrustPolicy` objects.
    var allPolicies: [TrustPolicy] { get }
    
    /// `TrustPolicy` object using a concrete validation method for a given host name.
    ///
    /// - Parameters:
    ///   - type:       The `ValidationType` enummeration values specify which kind
    ///                 of trust is created.
    ///
    ///   - hostName:   The host name URL as string that the policy applies for.
    ///
    ///                 The `TrustManager` handles policies by its name but
    ///                 it is also used for standard SSL validation where the
    ///                 server identity is verified by the host name URL.
    ///
    ///                 The host portion of the provided URL string should match
    ///                 `dnsName` field in the `subjectAltName` field of the certificate.
    ///
    ///                 By default the `hostName` URL string will be used by all non-custom
    ///                 trust validation checks, e.g. `ValidationType`: `.standard`,
    ///                 `.pinCertificate` and .pinPublicKey`)
    ///                 It is possible to skip the host name check by passing a
    ///                 `ValidationSettings` object with `skipHostNameValidation = true`.
    ///                 This allows to use an arbitrary string instead of an URL string.
    ///
    ///   - settings:   An optional `ValidationSettings` object.
    ///                 Can safely be omitted. In that case the default settings will be used.
    ///
    /// - Returns:  a new created `TrustPolicy` conforming object.
    func create(type: ValidationType, hostName: String, settings: ValidationSettings?) -> TrustPolicy
    
    /// Retrieve matching policy by its name.
    ///
    /// - Parameter name: the name of the policy
    /// - Returns: optional `TrustPolicy` conforming object
    func policy(for name: String) -> TrustPolicy?
    
    /// Adds a new `TrustPolicy` object.
    ///
    /// - Parameter policy: `TrustPolicy` conforming object
    func add(policy: TrustPolicy)
    
    /// Adds a batch of `TrustPolicy` objects at once.
    ///
    /// - Parameter policies: Array of `TrustPolicy` conforming objects
    func add(policies: [TrustPolicy])
    
    /// Remove a `TrustPolicy` by it's name.
    ///
    /// - Parameter name: the name with which the `TrustPolicy` was added
    /// - Returns: the removed `TrustPolicy` if removal was successful
    func removePolicy(name: String) -> TrustPolicy?
}
