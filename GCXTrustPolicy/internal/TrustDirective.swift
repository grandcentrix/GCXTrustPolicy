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
import OpenSSL
import CommonCrypto
import Pkcs7UnionAccessors // so swift sees the c structs


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
    
    fileprivate func sha256hex(data: Data) -> String? {
        var digestData = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        
        _ = digestData.withUnsafeMutableBytes {digestBytes in
            data.withUnsafeBytes {messageBytes in
                CC_SHA256(messageBytes, CC_LONG(data.count), digestBytes)
            }
        }
        return digestData.map { String(format: "%02hhx", $0) }.joined()
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


// MARK: - Default Online pinning -

/**
 The standart procedure to evaluate host by online pinned file
 */
class DefaultOnlineDirective: DefaultDirective {
    var trustServer: URL
    var trustCertificate: Data
    var trustStore: URL
    var customer: String
    
    init(trustServer: URL, trustServerCertificate: Data, customer: String, hostName: String, validateServerTrust: Bool, validateHost: Bool) {
        self.trustServer = trustServer
        self.trustCertificate = trustServerCertificate
        self.customer = customer
        
        let docsurl = try! FileManager.default.url(for:.documentDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        trustStore = docsurl.appendingPathComponent("trustedCertificates.json.signed")
        
        super.init(withHostName: hostName, validateServerTrust: validateServerTrust, validateHost: validateHost)
    }
    
    private func reloadPinningFileFromServer() {
        // this request must be syncron otherwise we cannot tell if the certs are pinned
        let semaphore = DispatchSemaphore(value: 0)
        let task = URLSession.shared.dataTask(with: self.trustServer) { data, response, error in
            // if error is nil and data is not nil we write the data to the trustStore
            if error == nil {
                if let data = data {
                    _ = try? data.write(to: self.trustStore) // if we cannot write to file, the validation will fail afterwards
                }
            }
            
            semaphore.signal()
        }
        
        task.resume()
        
        // we ignore the return value. If we hit the timeout it most probably will not happen in a second attempt.
        _ = semaphore.wait(timeout: DispatchTime.now() + 30) // in 30 seconds
    }
    
    func removeTrustStore() {
        do {
            let fileManager = FileManager.default
            if fileManager.fileExists(atPath: trustStore.path) {
                try fileManager.removeItem(atPath: trustStore.path)
            }
        } catch let error as NSError {
            print(error)
        }
    }
    
    /**
     * returnes Content of Trust Store for hostname, if the signature is correct.
     */
    fileprivate func loadTrustStore() -> [String: Any]? {
        let fileManager = FileManager.default
        var verifyTimestamp = false
        
        if !fileManager.fileExists(atPath: self.trustStore.path) {
            reloadPinningFileFromServer()
            
            // newly downloaded files need to check the timestamp
            verifyTimestamp = true
        }
        
        // if file still does not exists -> no trust at all -> panic
        if !fileManager.fileExists(atPath: self.trustStore.path) {
            return nil
        }
        
        // Loading the receipt file
        let receiptBIO = BIO_new(BIO_s_mem())
        if let receiptData = NSData(contentsOf: self.trustStore) {
            BIO_write(receiptBIO, receiptData.bytes, Int32(receiptData.length))
        } else {
            // Could not read receipt data => remove TrustStore so it is reloaded the next time
            removeTrustStore()
            return nil
        }
        
        // Parse the PKCS7 envelope
        let receiptPKCS7 = d2i_PKCS7_bio(receiptBIO, nil)
        
        if receiptPKCS7 == nil {
            // Receipt PKCS7 container parsing error => remove TrustStore
            removeTrustStore()
            return nil
        }
        
        // Check for a signature
        if OBJ_obj2nid(receiptPKCS7!.pointee.type) != NID_pkcs7_signed {
            // Receipt is not signed => remove TrustStore
            removeTrustStore()
            return nil
        }
        
        // Check for data
        if OBJ_obj2nid(pkcs7_d_sign(receiptPKCS7).pointee.contents.pointee.type) != NID_pkcs7_data {
            // Receipt does not contain signed data => remove TrustStore
            removeTrustStore()
            return nil
        }
        
        // Verify the receipt signature
        let pkBIO = BIO_new(BIO_s_mem())
        _ = self.trustCertificate.withUnsafeBytes{ pkBytes in
            BIO_write(pkBIO, pkBytes, Int32(self.trustCertificate.count))
        }
        
        
        let pkX509 = d2i_X509_bio(pkBIO, nil)
        let store = X509_STORE_new()
        X509_STORE_add_cert(store, pkX509)
        OpenSSL_add_all_digests()
        let result = PKCS7_verify(receiptPKCS7, nil, store, nil, nil, 0)
        if result != 1 {
            // Receipt signature verification failed => remove TrustStore
            removeTrustStore()
            return nil
        }
        
        
        // Extract the data set to be verified from the receipt
        let octets = pkcs7_d_data(pkcs7_d_sign(receiptPKCS7).pointee.contents)
        let ptr = UnsafePointer<UInt8>(octets!.pointee.data)
        let length = Int(octets!.pointee.length)
        
        let contentData = NSData(bytes: ptr, length: length)
        
        do {
            let parsedData = try JSONSerialization.jsonObject(with: contentData as Data, options: []) as! [String:Any]
            
            // check Timestamp
            if verifyTimestamp {
                let timestamp = parsedData["timestamp"] as! Double
                let currentTime = NSDate().timeIntervalSince1970
                if timestamp < 0 || (timestamp + 600) < currentTime { // check if file is not older than 10 minutes
                    // downloaded File is to old => remove trustfile
                    removeTrustStore()
                    return nil
                }
            }
            
            // check that the customer is correct
            let customer = parsedData["customer"] as! String
            
            if customer != self.customer {
                // Customer in JSON is not Correct => remove TrustStore
                removeTrustStore()
                return nil
            }
            
            for host in parsedData["hashes"] as! [[String: Any]] {
                if host["hostname"] as? String != self.hostName {
                    // The Hostname is not the correct => try the next
                    continue
                }

                return host
            }
            
            // return nil
            return nil
        } catch _ as NSError {
            // we cannot deserialize the JSON => remove TrustStore
            removeTrustStore()
            return nil
        }
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


// MARK: - Certificate pinning -

/**
 Pin the server certifcate by comparing the trusted certificate(s) against the remote one(s).
 */
class PinCertificateOnlineDirective: DefaultOnlineDirective {
    override func validate(with trust: SecTrust) -> Bool {
        return certificateOnlinePinningValidation(withTrust: trust, forceReload: false)
    }
    
    private func certificatePinningValidation(withTrust trust: SecTrust) -> Bool {
               return false
    }

    private func certificateOnlinePinningValidation(withTrust trust: SecTrust, forceReload: Bool) -> Bool {
        if forceReload {
            removeTrustStore()
        }
        
        if defaultValidation(withTrust: trust, skipValidation: !validateServerTrust) {
            let remoteCertificateDatas = TrustEvaluation.certificateData(from: trust)
            let pinnedFingerprints = loadPinnedFingerprints()
            for pinnedFingerprint in pinnedFingerprints {
                for remoteCertificateData in remoteCertificateDatas {
                    let remoteFingerprint = sha256hex(data: remoteCertificateData)
                    
                    if remoteFingerprint == pinnedFingerprint {
                        return true
                    }
                }
            }
        }
        
        // trigger reload and try again but only once
        if (!forceReload) {
            return certificateOnlinePinningValidation(withTrust: trust, forceReload: true)
        } else {
            return false
        }
    }
    
    private func loadPinnedFingerprints() -> [String] {
        let trustStoreData = loadTrustStore()
        
        // load fingerprints from Truststore
        guard let fingerprints = trustStoreData?["fp"] else {
            return []
        }
        
        return fingerprints as! [String]
    }
}


// MARK: - Public key pinning -

/**
 Perform standard validation and check for matching public keys in certificate chain.
 */
class PinPublicKeyOnlineDirective: DefaultOnlineDirective {
    override func validate(with trust: SecTrust) -> Bool {
        return keyPinningOnlineValidation(withTrust: trust, forceReload: false)
    }
    
    private func keyPinningOnlineValidation(withTrust trust: SecTrust, forceReload: Bool) -> Bool {
        if forceReload {
            removeTrustStore()
        }
        
        if defaultValidation(withTrust: trust, skipValidation: !validateServerTrust) {
            let pinnedPublicKeys = loadPinnedPublicKeys()
            for pinnedPublicKey in pinnedPublicKeys  as [AnyObject] {
                for remotePublicKey in TrustEvaluation.publicKeys(from: trust) as [AnyObject] {
                    if pinnedPublicKey.isEqual(remotePublicKey) {
                        return true
                    }
                }
            }
        }

        // trigger reload and try again but only once
        if (!forceReload) {
            return keyPinningOnlineValidation(withTrust: trust, forceReload: true)
        } else {
            return false
        }
    }
    
    private func loadPinnedPublicKeys() -> [SecKey] {
        let trustStoreData = loadTrustStore()
        
        // load publicKeys from Truststore
        guard let rawKeys = trustStoreData?["pk"] else {
            return []
        }
        
        var keys: [SecKey] = []
        for raw in rawKeys as! [String] {
            if let keyData = Data(base64Encoded: raw) {
                var error: Unmanaged<CFError>? = nil
                
                // On iOS 10+, we can use SecKeyCreateWithData without going through the keychain
                if #available(iOS 10.0, *), #available(watchOS 3.0, *), #available(tvOS 10.0, *) {
                    let sizeInBits = keyData.count * 8
                    let keyDict: [String: AnyObject] = [
                        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                        kSecAttrKeySizeInBits as String: NSNumber(value: sizeInBits)
                    ]
                    
                    if let key = SecKeyCreateWithData(keyData as CFData, keyDict as CFDictionary, &error) {
                        keys.append(key)
                    }
                    
                    // On iOS 9 and earlier, add a persistent version of the key to the system keychain
                } else {
                    let persistKey = UnsafeMutablePointer<AnyObject?>(mutating: nil)
                    
                    let keyAddDict: [String: AnyObject] = [
                        kSecClass as String: kSecClassKey,
                        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                        kSecValueData as String: keyData as CFData,
                        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                        kSecReturnPersistentRef as String: NSNumber(value: true),
                        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
                    ]
                    
                    let secStatus = SecItemAdd(keyAddDict as CFDictionary, persistKey)
                    guard secStatus == errSecSuccess || secStatus == errSecDuplicateItem else {
                        continue
                    }
                    
                    let keyCopyDict: [String: AnyObject] = [
                        kSecClass as String: kSecClassKey,
                        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
                        kSecReturnRef as String: NSNumber(value: true),
                        ]
                    
                    // Now fetch the SecKeyRef version of the key
                    var keyRef: AnyObject? = nil
                    _ = SecItemCopyMatching(keyCopyDict as CFDictionary, &keyRef)
                    
                    guard let unwrappedKeyRef = keyRef else {
                        continue
                    }
                    
                    // delete the key
                    SecItemDelete(keyAddDict as CFDictionary)
                    
                    keys.append(unwrappedKeyRef as! SecKey) // swiftlint:disable:this force_cast
                }
            }
        }
        
        return keys
    }
}

