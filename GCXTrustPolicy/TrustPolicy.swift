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

@objc(GCXTrustPolicy)
/// Protocol definition for validating a policy against a remote trust
public protocol TrustPolicy {
    
    /// Name of the host
    var hostName: String! { get set }
    
    /// Validates a policy against a given trust
    func validate(trust: SecTrust) -> Bool
}

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
