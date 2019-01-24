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


////////////////////////////////////////////////
///
/// TrustDirective
///
////////////////////////////////////////////////

import Foundation

// MARK: - Base class for validation -

class TrustDirective: NSObject, TrustPolicy {
    

    // MARK: - Variables -
    
    var hostName: String!
    
    fileprivate var validateServerTrust: Bool!
    fileprivate var validateHost: Bool!
    
    
    // MARK: - Initialisation -
    
    override init() {
        NSException(name: NSExceptionName(rawValue: "Unintended initialisation"),
                    reason: "Please use a concrete child class to perform initialisation.",
                    userInfo: nil).raise()
    }
    
    fileprivate init(withHostName host: String, validateServerTrust: Bool, validateHost: Bool) {
        self.hostName = host
        self.validateServerTrust = validateServerTrust
        self.validateHost = validateHost
        
        super.init()
    }
    
    
    // MARK: - TrustPolicy -
    
    func validate(with trust: SecTrust) -> Bool {
        return false
    }
}


// MARK: - Disabled validation -

/**
  Skip any validation and return a false success instead.
 */
class DisabledDirective: TrustDirective {
    
    init(withHostName host: String) {
        super.init(withHostName: host, validateServerTrust: false, validateHost: false)
    }
    
    override func validate(with trust: SecTrust) -> Bool {
        return true // no validation is performed
    }
}


// MARK: - Standard validation -

/**
  The standard procedure. Evaluate host and certificate chain for successful trust.
 */
class DefaultDirective: TrustDirective {
    
    override init(withHostName host: String, validateServerTrust: Bool, validateHost: Bool) {
        super.init(withHostName: host, validateServerTrust: validateServerTrust, validateHost: validateHost)
    }
    
    override func validate(with trust: SecTrust) -> Bool {
        return defaultValidation(withTrust: trust)
    }
    
    fileprivate func defaultValidation(withTrust trust: SecTrust, skipValidation: Bool = false) -> Bool {
        var isServerTrustValidationSuccessful = true
        if !skipValidation {
            let host: String? = validateHost ? hostName : nil
            isServerTrustValidationSuccessful = TrustEvaluation.isValid(serverTrust: trust, hostName: host)
        }
        return isServerTrustValidationSuccessful
    }
}


// MARK: - Custom validation -

/**
  Using a closure to perform a customized validation.
 */
class CustomDirective: DefaultDirective {
    
    var validationClosure: CustomValidationClosure

    
    init(withHostName host: String, customValidation: @escaping CustomValidationClosure) {
        self.validationClosure = customValidation
        
        super.init(withHostName: host, validateServerTrust: false, validateHost: false)
    }
    
    override func validate(with trust: SecTrust) -> Bool {
        return customValidation(withTrust: trust)
    }
    
    fileprivate func customValidation(withTrust trust: SecTrust) -> Bool {
        return validationClosure(trust)
    }
}


// MARK: - Certificate pinning -

/**
  Pin the server certifcate by comparing the local certificate(s) against the remote one(s).
 */
class PinCertificateDirective: DefaultDirective {
    
    var pinnedCertificateDatas: [Data]
    
    init(certificateBundle bundle: Bundle, hostName: String, validateServerTrust: Bool, validateHost: Bool) {
        let certificates = TrustEvaluation.readDERCertificates(in: bundle)
        pinnedCertificateDatas = TrustEvaluation.certificateData(from: certificates)
        
        super.init(withHostName: hostName, validateServerTrust: validateServerTrust, validateHost: validateHost)
    }
    
    override func validate(with trust: SecTrust) -> Bool {
        return certificatePinningValidation(withTrust: trust)
    }
    
    fileprivate func certificatePinningValidation(withTrust trust: SecTrust) -> Bool {
        if defaultValidation(withTrust: trust, skipValidation: !validateServerTrust) {
            let remoteCertificateDatas = TrustEvaluation.certificateData(from: trust)
            for pinnedCertificateData in pinnedCertificateDatas {
                for remoteCertificateData in remoteCertificateDatas {
                    if (pinnedCertificateData as Data) == remoteCertificateData {
                        return true
                    }
                }
            }
        }
        return false
    }
}


// MARK: - Public key pinning -

/**
  Perform standard validation and check for matching public keys in certificate chain.
 */
class PinPublicKeyDirective: DefaultDirective {
    
    var pinnedPublicKeys: [SecKey]

    init(certificateBundle bundle: Bundle, hostName: String, validateServerTrust: Bool, validateHost: Bool) {
        pinnedPublicKeys = TrustEvaluation.publicKeysFromCertificates(in: bundle)
        
        super.init(withHostName: hostName, validateServerTrust: validateServerTrust, validateHost: validateHost)
    }

    override func validate(with trust: SecTrust) -> Bool {
        return keyPinningValidation(withTrust: trust)
    }

    fileprivate func keyPinningValidation(withTrust trust: SecTrust) -> Bool {
        if defaultValidation(withTrust: trust, skipValidation: !validateServerTrust) {
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
