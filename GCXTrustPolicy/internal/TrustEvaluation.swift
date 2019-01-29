//
//  TrustEvaluation.swift
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

class TrustEvaluation {

    // MARK: - Certificate data operations -
    
    /// Extract the binary data from an array of certificates.
    ///
    /// - Parameter certificates: array of certificates
    /// - Returns: array of certificate data
    static func certificateData(from certificates: [SecCertificate]) -> [Data] {
        return certificates.map { SecCertificateCopyData($0) as Data }
    }
    
    /// Retrieve certificate datas from a trust management object.
    ///
    /// - Parameter trust: a trust management object
    /// - Returns: array of data
    static func certificateData(from trust: SecTrust) -> [Data] {
        var certificates: [SecCertificate] = []
        
        // loop through trust and retrieve certificates
        for index in 0..<SecTrustGetCertificateCount(trust) {
            if let certificate = SecTrustGetCertificateAtIndex(trust, index) {
                certificates.append(certificate)
            }
        }
        
        return certificateData(from: certificates)
    }
    
    // MARK: - Bundle certificate operations -
    
    /// Extract the public keys from certificates.
    ///
    /// - Parameter bundle: the bundle to load from
    /// - Returns: array of public keys
    static func publicKeysFromCertificates(in bundle: Bundle = Bundle.main) -> [SecKey] {
        return readDERCertificates(in: bundle)
                .map { publicKey(from: $0) }
                .compactMap { $0 }
    }
    
    /// Load certificates in DER representation from bundle with file ending 'cer'.
    ///
    /// - Parameter bundle: the bundle to load from.
    /// - Returns: array of certificate objects
    static func readDERCertificates(in bundle: Bundle = Bundle.main) -> [SecCertificate] {
        return bundle
                .paths(forResourcesOfType: "cer", inDirectory: nil)
                .map { readSecCertificate(from: $0) }
                .compactMap { $0 }
    }
    
    /// Read certificate data from a file path.
    ///
    /// - Parameter path: the path to a file in string representation
    /// - Returns: the optional SecCertificate data
    static func readSecCertificate(from path: String) -> SecCertificate? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return nil
        }
        return SecCertificateCreateWithData(nil, data as CFData)
    }
    
    // MARK: - Public key extraction -

    /// Retrieve the public keys from a trust.
    ///
    /// - Parameter trust: the trust management object
    /// - Returns: array of public keys
    static func publicKeys(from trust: SecTrust) -> [SecKey] {
        var publicKeys: [SecKey] = []
        
        // loop through certificate data of the trust and extract their public key
        for index in 0..<SecTrustGetCertificateCount(trust) {
            if let certificate = SecTrustGetCertificateAtIndex(trust, index),
                let publicKey = publicKey(from: certificate) {
                publicKeys.append(publicKey)
            }
        }
        
        return publicKeys
    }
    
    /// Create certificate object from the certificate in DER representation.
    ///
    /// - Parameter certificate: a certificate object
    /// - Returns: an optional public key
    static func publicKey(from certificate: SecCertificate) -> SecKey? {
        
        // trust management object for performing X.509 certificate trust evaluations
        var trust: SecTrust?
        
        // ceate a default X.509 policy
        let policy = SecPolicyCreateBasicX509()
        
        // create a trust management object based on certificates and policies
        let trustCreationStatus = SecTrustCreateWithCertificates(certificate, policy, &trust)
        
        guard let successfulTrust = trust, trustCreationStatus == errSecSuccess else {
            return nil
        }
        
        // return the public key for a leaf certificate after it has been evaluated
        return SecTrustCopyPublicKey(successfulTrust)
    }
    
    // MARK: - Trust evaluation -
    
    /// Inspect a trust for valid certificate chain and host name.
    ///
    /// - Parameters:
    ///   - trust: the trust management object
    ///   - hostName: the challenged host`s name
    /// - Returns: Bool value telling if the trust is valid or not valid
    static func isValid(serverTrust trust: SecTrust, hostName: String?) -> Bool {
        
        // create a SSL policy object
        let host = hostName as CFString?
        let policy = SecPolicyCreateSSL(true, host ?? nil)
        
        // define the policies to use for evaluating the SSL certificate chain
        SecTrustSetPolicies(trust, policy)
        
        return evaluate(serverTrust: trust)
    }
  
    /// Evaluates a given trust for integrity and validity as SecTrustEvaluate
    /// performs customary X.509 checks.
    /// Unusual conditions will cause the function to return with no-success.
    /// Unusual conditions also include an expired certifcate or self signed certifcate.
    /// If it is needed to respond to those unusual conditions it is also possible
    /// to override the TLS chain validation and add the insecure certificate to
    /// the SecTrust.
    /// https://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/NetworkingTopics/Articles/OverridingSSLChainValidationCorrectly.html
    ///
    /// - Parameter trust: the trust management object
    /// - Returns: Bool value telling if the trust is valid or not valid
    static func evaluate(serverTrust trust: SecTrust) -> Bool {
        
        // the result type for trust evaluations
        var trustResult = SecTrustResultType.invalid
        
        // evaluate trust for the specified certificate and policies
        let evaluationStatus = SecTrustEvaluate(trust, &trustResult)
        
        // assume validity if the certificate is at least implicitly trusted
        if evaluationStatus == errSecSuccess {
            let unspecified = SecTrustResultType.unspecified
            let proceed = SecTrustResultType.proceed
            return (trustResult == unspecified || trustResult == proceed)
        }
        
        return false
    }
}
