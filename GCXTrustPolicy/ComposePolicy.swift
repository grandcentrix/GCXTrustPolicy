//
//  ComposePolicy.swift
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


/// Abstraction layer to simplify the creation of a 'TrustPolicy' conforming objects.
@objc(GCXComposePolicy)
open class ComposePolicy: NSObject {
    
    /// Skip certificate chain validation during standard X.509 validation.
    /// e.g. performing validation with servers that use self-signed
    /// or expired certificates
    ///
    /// Taken into account only for:
    /// ValidationType.pinPublicKey and ValidationType.pinCertificate
    ///
    /// Default setting is 'false'.
    @objc open var allowInsecureServerTrust = false
    
    /// Define if the host name(s) will be checked during the standard X.509 validation.
    ///
    /// This value is completely ignored if validation is skipped by setting
    /// 'allowInsecureServerTrust = true'.
    ///
    /// Default setting is 'true'.
    @objc open var validateHostName = true
    
    /// The bundle where to search for certificates.
    ///
    /// Taken into account only for:
    /// ValidationType.pinPublicKey and ValidationType.pinCertificate
    ///
    /// Default setting is the main Bundle.
    @objc open var certificateBundle = Bundle.main
    
    /// A custom closure for validation with ValidationType.custom.
    @objc open var customValidation: CustomValidationClosure?
    
    /// The validation type of the trust policy.
    open var validationType: ValidationType!
    
    /// The host name that the policy applies for.
    @objc open var hostName: String!
    
    /// the TrustServer for validation with ValidationType.*Online
    @objc open var trustServer: URL?
    @objc open var trustServerCertificate: Data?
    @objc open var customer: String?

    
    
    /** 
      Not available.
      Use the designated initializer instead.
     */
    fileprivate override init() {
        super.init()
        NSException(name: NSExceptionName(rawValue: "Unintended instantiation"),
                    reason: "Please use the designated initializer to construct object.",
                    userInfo: nil).raise()
    }
    
    
    /**
      Prepare the creation of the final 'TrustPolicy' object for a given
      host name. Use the 'ValidationType' enummeration values to specify
      which type of trust is desired.
     
      - parameter type:     the policy type
      - parameter forHost:  the host name
     
      - returns: an instance of this class
     */
    @objc public init(withValidation type: ValidationType, forHost host: String) {
        self.validationType = type
        self.hostName = host

        super.init()
    }
    
    
    /**
      Concrete creator for the 'TrustPolicy' conforming object
     
      - returns: an object of type 'TrustDirective' conforming to 'TrustPolicy' protocol
     */
    @objc open func create() -> TrustPolicy {
        
        // A concrete builder creating the final TrustPolicy object.
        var concreteBuilder: AbstractBuilder!
        
        switch validationType! {
            
        case .disabled:
            let builder = DisabledBuilder(withHostName: hostName)
            concreteBuilder = builder
            
        case .standard:
            let builder = DefaultBuilder(withHostName: hostName)
            builder.validateHost = validateHostName
            builder.allowInsecureTrust = false
            concreteBuilder = builder
         
        case .custom:
            if let closure = customValidation {
                let builder = CustomBuilder(withHostName: hostName)
                builder.customValidation = closure
                concreteBuilder = builder
            } else {
                NSException(name: NSExceptionName(rawValue: "Missing Parameter"),
                            reason: "Please provide a custom validation closure.",
                            userInfo: nil).raise()
            }
            
        case .pinCertificate:
            let builder = CertificateBuilder(withHostName: hostName)
            builder.validateHost = validateHostName
            builder.allowInsecureTrust = allowInsecureServerTrust
            builder.certificateBundle = certificateBundle
            concreteBuilder = builder
            
        case .pinPublicKey:
            let builder = PublicKeyBuilder(withHostName: hostName)
            builder.validateHost = validateHostName
            builder.allowInsecureTrust = allowInsecureServerTrust
            builder.certificateBundle = certificateBundle
            concreteBuilder = builder
            
        case .pinCertificateOnline:
            let builder = CertificateOnlineBuilder(withHostName: hostName)
            builder.validateHost = validateHostName
            builder.allowInsecureTrust = allowInsecureServerTrust
            
            // add infos for TrustServer
            if let closure = trustServer {
                builder.trustServer = closure
            } else {
                NSException(name: NSExceptionName(rawValue: "Missing Parameter"),
                            reason: "Please provide a TrustServer closure.",
                            userInfo: nil).raise()

            }
            
            if let closure = trustServerCertificate {
                builder.trustServerCertificate = closure
            } else {
                NSException(name: NSExceptionName(rawValue: "Missing Parameter"),
                            reason: "Please provide a TrustServerCertificate closure.",
                            userInfo: nil).raise()
            }

            if let closure = customer {
                builder.customer = closure
            } else {
                NSException(name: NSExceptionName(rawValue: "Missing Parameter"),
                            reason: "Please provide a Customer closure.",
                            userInfo: nil).raise()
            }

            concreteBuilder = builder
            
        case .pinPublicKeyOnline:
            let builder = PublicKeyOnlineBuilder(withHostName: hostName)
            builder.validateHost = validateHostName
            builder.allowInsecureTrust = allowInsecureServerTrust
            
            // add infos for TrustServer
            if let closure = trustServer {
                builder.trustServer = closure
            } else {
                NSException(name: NSExceptionName(rawValue: "Missing Parameter"),
                            reason: "Please provide a TrustServer closure.",
                            userInfo: nil).raise()
                
            }
            
            if let closure = trustServerCertificate {
                builder.trustServerCertificate = closure
            } else {
                NSException(name: NSExceptionName(rawValue: "Missing Parameter"),
                            reason: "Please provide a TrustServerCertificate closure.",
                            userInfo: nil).raise()
            }
            
            if let closure = customer {
                builder.customer = closure
            } else {
                NSException(name: NSExceptionName(rawValue: "Missing Parameter"),
                            reason: "Please provide a Customer closure.",
                            userInfo: nil).raise()
            }

            concreteBuilder = builder
            
        }
        
        return concreteBuilder.build()
    }
}
