//
//  DataTypesProtocols.swift
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

/// type alias for a closre that provides custom validation
public typealias CustomValidationClosure = (SecTrust?) -> (Bool)

@objc(GCXTrustPolicy)
/// Protocol definition for validating a policy against a remote trust
public protocol TrustPolicy {
    
    /// Name of the host
    var hostName: String! { get set }
    
    /// Validates a policy against a given trust
    func validate(trust: SecTrust) -> Bool
}

@objc(GCXTrustComposing)
/// Protocol defining the creation of 'TrustPolicy' conforming objects.
public protocol TrustComposing {
    
    /// Prepares creation of a `TrustPolicy` object for a given host name.
    /// The `ValidationType` enummeration values specify which kind of
    /// trust is constucted upon `create()` call.
    ///
    /// - Parameters:
    ///   - type: `ValidationType` the policy type
    ///   - host:  optional host name String
    init(with type: ValidationType, for host: String?)
    
    /// Creation method for a new `TrustPolicy'
    ///
    /// - Returns: a new created `TrustPolicy` conforming objects.
    func create() -> TrustPolicy
    
    /// The host name that the policy applies for.
    ///
    /// Will also used by all non-custom trust validation checks
    /// (e.g. `ValidationType`: `.standard`, `.pinCertificate`,
    /// .pinPublicKey`)
    ///
    /// Leaving the host name unset will lead the system not take it into
    /// account during X.509 validation, hence it should be provided
    /// by the calling client.
    var hostName: String? { get set }
    
    /// The bundle where to search for certificates.
    /// These certificates have to be bundled with the app.
    /// (e.g. Xcode project folder)
    ///
    /// Taken into account only for certificate required
    /// `ValidationType`:`.pinPublicKey` and `.pinCertificate`.
    ///
    /// Default setting is the main Bundle.
    var certificateBundle: Bundle { get set }
    
    /// A custom closure for validation with `ValidationType`: `.custom`.
    /// When using this, all validation logic has to be contained in
    /// the closure.
    /// A host name check, as part of systems standard
    /// X.509 validation, is not being performed as well.
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
    func removePolicy(name: String)
}
