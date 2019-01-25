//
//  TrustComposer.swift
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

@objc(GCXTrustComposing)
/// Protocol defining the creation of 'TrustPolicy' conforming objects.
public protocol TrustComposing {

    /// Prepares creation of a `TrustPolicy` object for a given host name.
    /// The `ValidationType` enummeration values specify which kind of
    /// trust is constucted upon `create()` call.
    ///
    /// - Parameters:
    ///   - type: `ValidationType` the policy type
    ///   - host:  host name String
    init(with type: ValidationType, for host: String)
    
    /// Creation method for a new `TrustPolicy'
    ///
    /// - Returns: a new created `TrustPolicy` conforming objects.
    func create() -> TrustPolicy

    /// The host name that the policy applies for.
    var hostName: String { get set }
    
    /// Define if host name checks will be skipped the standard X.509 validation.
    ///
    /// Default setting is 'false'.
    var skipHostNameValidation: Bool { get set }
    
    /// The bundle where to search for certificates.
    ///
    /// Taken into account only for certificate validation types:
    /// `ValidationType.pinPublicKey` and `ValidationType.pinCertificate`
    ///
    /// Default setting is the main Bundle.
   var certificateBundle: Bundle { get set }
    
    /// Skip certificate chain validation during standard X.509 validation.
    /// Careful with this option as it allows an unsecure server trust.
    /// Can be useful when performing validation with servers that use self-signed
    /// or expired certificates.
    ///
    /// Taken into account only for:
    /// `ValidationType.pinPublicKey` and `ValidationType.pinCertificate`
    ///
    /// Default setting is `false`.
    var certificateSkipChainValidation: Bool { get set }
    
    /// A custom closure for validation with `ValidationType.custom`.
    var customValidation: CustomValidationClosure? { get set }
}

/// Abstraction layer to simplify the creation of 'TrustPolicy' conforming objects.
@objc(GCXTrustComposer)
open class TrustComposer: NSObject, TrustComposing {
    
    public var validationType: ValidationType = .standard
    public var hostName = "undefined"
    public var skipHostNameValidation = false
    public var certificateBundle = Bundle.main
    public var certificateSkipChainValidation = false
    public var customValidation: CustomValidationClosure?
    
    /// Defauilt initializer is not available. Use the designated initializer instead.
    private override init() {
        super.init()
        
        let name = NSExceptionName(rawValue: "Unintended instantiation")
        let reason = "Please use the designated initializer to construct object."
        NSException(name: name, reason: reason, userInfo: nil).raise()
    }
    
    required public init(with type: ValidationType, for host: String) {
        self.validationType = type
        self.hostName = host

        super.init()
    }
    
    open func create() -> TrustPolicy {
        switch validationType {
        case .disabled:
            return DisabledDirective(withHostName: hostName)
            
        case .standard:
            return DefaultDirective(withHostName: hostName, validateServerTrust: true, validateHost: skipHostNameValidation)
            
        case .custom:
            if customValidation == nil {
                let name = NSExceptionName(rawValue: "Missing Parameter")
                let reason = "Please provide a custom validation closure."
                NSException(name: name, reason: reason, userInfo: nil).raise()
            }
            return CustomDirective(withHostName: hostName, customValidation: customValidation!)
            
        case .pinCertificate:
            return PinCertificateDirective(certificateBundle: certificateBundle, hostName: hostName, validateServerTrust: certificateSkipChainValidation, validateHost: skipHostNameValidation)
            
        case .pinPublicKey:
            return PinPublicKeyDirective(certificateBundle: certificateBundle, hostName: hostName, validateServerTrust: certificateSkipChainValidation, validateHost: skipHostNameValidation)
        }
    }
}
