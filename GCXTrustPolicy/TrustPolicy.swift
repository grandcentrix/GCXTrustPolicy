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

/// Protocol definition for validating a policy against a remote trust
@objc(GCXTrustPolicy)
public protocol TrustPolicy {
    
    /// The name of the host
    var hostName: String! { get set }
    
    /// Validates a policy against a given trust
    func validate(with trust: SecTrust) -> Bool
}


/**
  Enummeration of all trust policy validation types.
 
  - disabled:           Perform no validation at all.
                        Be careful, this will always consider any server trust as valid.
 
  - standard:           Perform a standard validation.
                        Using the system provided standard mechanism that is basically a
                        X.509 certificate trust evaluation in a recursive two-step
                        process down to the trusted anchor certificate.

 - custom:              Perform a completely custom validation.
                        The validation process is completely up to you.
 
 - pinCertificate:      Perform a validation by pinning certificate(s).
                        The validation process is considered successful if one of the pinned
                        certificates match one of the servers certificates and standard
                        validation has also been successful.
 
 - pinPublicKey:        Perform a validation by pinning the certificate(s) public key.
                        The validation process is considered successful if one of the pinned
                        public key(s) match one of the servers public key(s) and standard
                        validation has also been successful.
 */
@objc(GCXValidationType) public enum ValidationType: Int {
    case disabled = 0
    case standard
    case custom
    case pinCertificate
    case pinPublicKey
}


/// Custom validation closure type alias
public typealias CustomValidationClosure = (SecTrust?) -> (Bool)
