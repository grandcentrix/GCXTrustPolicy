//
//  TrustDirective.swift
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

/// Abstract base class for different trust directives represented via `ValidationType` enum.
class AbstractDirective: NSObject, TrustPolicy {

    var hostName: String?
    
    override init() {
        let name = NSExceptionName(rawValue: "Unintended initialisation")
        let reason = "Please use a concrete child class to perform initialisation."
        NSException(name: name, reason: reason, userInfo: nil).raise()
    }
    
    init(hostName: String?) {
        self.hostName = hostName
        super.init()
    }
    
    func validate(trust: SecTrust) -> Bool {
        return false // intended to override in subclass
    }
}

/// Skip any validation and return a false success instead.
class DisabledDirective: AbstractDirective {
    
    override func validate(trust: SecTrust) -> Bool {
        return true // no validation is performed
    }
}

/// Uses a closure passed to the object to perform a completely custom validation.
class CustomDirective: AbstractDirective {
    
    var validationClosure: CustomValidationClosure?
    
    init(hostName: String?, customValidation: CustomValidationClosure?) {
        self.validationClosure = customValidation
        
        super.init(hostName: hostName)
    }
    
    override func validate(trust: SecTrust) -> Bool {
        guard let closure = validationClosure else { return false } // validation fails without
        return closure(trust)
    }
}

/// The standard validation. Evaluate host and certificate chain for successful trust.
class DefaultDirective: AbstractDirective {
    
    override func validate(trust: SecTrust) -> Bool {
        return defaultValidation(trust: trust)
    }
    
    /// Triggers a standard X.509 validation check
    func defaultValidation(trust: SecTrust) -> Bool {
        return TrustEvaluation.isValid(serverTrust: trust, hostName: hostName)
    }
}

/// Build upon `DefaultDirective` and pins the server certifcate
/// by comparing the local certificate(s) against the remote one(s).
class PinCertificateDirective: DefaultDirective {
    
    var pinnedCertDatas: [Data]
    
    init(hostName: String?, certificateBundle: Bundle) {
        let certificates = TrustEvaluation.readDERCertificates(in: certificateBundle)
        pinnedCertDatas = TrustEvaluation.certificateData(from: certificates)
        
        super.init(hostName: hostName)
    }
    
    override func validate(trust: SecTrust) -> Bool {
        if defaultValidation(trust: trust) {
            let remoteCertData = TrustEvaluation.certificateData(from: trust)
            for pinnedData in pinnedCertDatas {
                for remoteData in remoteCertData {
                    if (pinnedData as Data) == remoteData {
                        return true
                    }
                    
                }
            }
        }
        return false
    }
}

/// Build upon `DefaultDirective` and pins the server certifcate and performs
/// standard validation and check for matching public keys in certificate chain.
class PinPublicKeyDirective: DefaultDirective {
    
    var pinnedPublicKeys: [SecKey]

    init(hostName: String?, certificateBundle: Bundle) {
        pinnedPublicKeys = TrustEvaluation.publicKeysFromCertificates(in: certificateBundle)
        
        super.init(hostName: hostName)
    }

    override func validate(trust: SecTrust) -> Bool {
        return keyPinningValidation(trust: trust)
    }

    fileprivate func keyPinningValidation(trust: SecTrust) -> Bool {
        if defaultValidation(trust: trust) {
            for pinnedPublicKey in pinnedPublicKeys as [AnyObject] {
                for remotePublicKey in TrustEvaluation.publicKeys(from: trust) as [AnyObject] {
                    if pinnedPublicKey.isEqual(remotePublicKey) {
                        return true
                    }
                }
            }
        }
        return false
    }
}
