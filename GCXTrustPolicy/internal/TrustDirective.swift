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

    var hostName: String
    var settings: ValidationSettings
    
    init(hostName: String, settings: ValidationSettings) {
        self.hostName = hostName
        self.settings = settings
        
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
    
    override func validate(trust: SecTrust) -> Bool {
        guard let closure = settings.customValidation else { return false } // validation fails without
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
        return TrustEvaluation.isValid(serverTrust: trust, hostName: settings.sslValidateHostName ? hostName : nil)
    }
}

/// Build upon `DefaultDirective` and pins the server certifcate
/// by comparing the local certificate(s) against the remote one(s).
class PinCertificateDirective: DefaultDirective {
    
    var pinnedCertDatas: [Data]!
    
    override init(hostName: String, settings: ValidationSettings) {
        super.init(hostName: hostName, settings: settings)
        
        let certificates = TrustEvaluation.readDERCertificates(in: settings.certificateBundle)
        pinnedCertDatas = TrustEvaluation.certificateData(from: certificates)
    }
    
    override func validate(trust: SecTrust) -> Bool {
        if settings.certificatePinOnly  {
            return verifyCertificate(trust: trust)
        }
        
        if defaultValidation(trust: trust) {
            return verifyCertificate(trust: trust)
        }
        
        return false
    }
    
    func verifyCertificate(trust: SecTrust) -> Bool {
        let remoteCertData = TrustEvaluation.certificateData(from: trust)
        for pinnedData in pinnedCertDatas {
            for remoteData in remoteCertData {
                if (pinnedData as Data) == remoteData {
                    return true
                }
            }
        }
        return false
    }
}

/// Build upon `DefaultDirective` and pins the server certifcate and performs
/// standard validation and check for matching public keys in certificate chain.
class PinPublicKeyDirective: DefaultDirective {
    
    var pinnedPublicKeys: [SecKey]!

    override init(hostName: String, settings: ValidationSettings) {
        super.init(hostName: hostName, settings: settings)
        
        pinnedPublicKeys = TrustEvaluation.publicKeysFromCertificates(in: settings.certificateBundle)
    }
    
    override func validate(trust: SecTrust) -> Bool {
        if settings.certificatePinOnly  {
            return verifyCertificate(trust: trust)
        }
        
        if defaultValidation(trust: trust) {
            return verifyCertificate(trust: trust)
        }
        
        return false
    }
    
    func verifyCertificate(trust: SecTrust) -> Bool {
        for pinnedPublicKey in pinnedPublicKeys as [AnyObject] {
            for remotePublicKey in TrustEvaluation.publicKeys(from: trust) as [AnyObject] {
                if pinnedPublicKey.isEqual(remotePublicKey) {
                    return true
                }
            }
        }
        return false
    }
}
