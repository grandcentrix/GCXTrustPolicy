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

/// type alias for a closre that provides custom validation
public typealias CustomValidationClosure = (SecTrust?) -> (Bool)

@objc(GCXValidationType)
/// Trust policy validation types.
///
/// - disabled: Performs no validation at all.
///				It is advised to be careful with disabling validation
///				because *any* server trust will always be considerd as valid.
///
/// - standard: Performs a standard validation.
///				Using the system provided standard mechanism that is basically a
///				X.509 certificate trust evaluation in a recursive two-step
///				process down to the trusted anchor certificate.
///
/// - custom:	Performx a completely custom validation.
///				Handling the validation process is completely up to the developer.
///
/// - pinCertificate: 	Perform a validation by pinning certificate(s).
///						The validation process is considered successful if one of the pinned
///						public key(s) match one of the servers public key(s) and standard
///						X.509 trust validation has also been successful.
///
/// - pinPublicKey:     Perform a validation by pinning the certificate(s) public key.
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
    ///   - hostName:   Passing a `hostName` String is optional but leaving it unset
    ///                 will lead the system not take the host`s name into account
    ///                 during X.509 validation, hence it should be provided
    ///                 by the calling client.
    ///                 The `hostName` String will be used by all non-custom trust
    ///                 validation checks (e.g. `ValidationType`: `.standard`,
    ///                 `.pinCertificate`, .pinPublicKey`)
    ///
    ///   - certificateBundle:  The bundle where to search for certificates.
    ///                         These certificates have to be bundled with the app.
    ///                         (e.g. Xcode project folder)
    ///                         Taken into account only for certificate required
    ///                         validation `ValidationType`:`.pinPublicKey`
    ///                         and `.pinCertificate`.
    ///                         If omitted or `nil` param is passed the main Bundle
    ///                         is assumed as default location for certificates.
    ///
    ///   - customValidation:   A custom closure for validation with `ValidationType`:
    ///                         `.custom`. When using this, all validation logic has
    ///                         to be contained within the closure.
    ///                         A host name check, as part of systems standard
    ///                         X.509 validation, is not done on custom validation and
    ///                         and has to be handled by the caller.
    ///                         Swift default value is `nil`.
    ///
    /// - Returns: a new created `TrustPolicy` conforming object.
    func create(type: ValidationType, hostName: String?, certificateBundle: Bundle?, customValidation: CustomValidationClosure?) -> TrustPolicy
    
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
