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

/// Abstraction layer to simplify the creation of 'TrustPolicy' conforming objects.
@objc(GCXTrustComposer)
open class TrustComposer: NSObject, TrustComposing {
    
    public var validationType: ValidationType = .standard
    public var hostName: String?
    public var certificateBundle = Bundle.main
    public var customValidation: CustomValidationClosure?
    
    /// Defauilt initializer is not available. Use the designated initializer instead.
    private override init() {
        super.init()
        
        let name = NSExceptionName(rawValue: "Unintended instantiation")
        let reason = "Please use the designated initializer to construct object."
        NSException(name: name, reason: reason, userInfo: nil).raise()
    }
    
    required public init(with type: ValidationType, for host: String?) {
        self.validationType = type
        self.hostName = host

        super.init()
    }
    
    open func create() -> TrustPolicy {
        switch validationType {
        case .disabled:
            return DisabledDirective(hostName: hostName)
            
        case .standard:
            return DefaultDirective(hostName: hostName)
            
        case .custom:
            if customValidation == nil {
                let name = NSExceptionName(rawValue: "Missing Parameter")
                let reason = "Please provide a custom validation closure."
                NSException(name: name, reason: reason, userInfo: nil).raise()
            }
            return CustomDirective(hostName: hostName, customValidation: customValidation!)
            
        case .pinCertificate:
            return PinCertificateDirective( hostName: hostName, certificateBundle: certificateBundle)
            
        case .pinPublicKey:
            return PinPublicKeyDirective(hostName: hostName, certificateBundle: certificateBundle)
        }
    }
}
