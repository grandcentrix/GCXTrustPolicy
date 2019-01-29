//
//  TestHelper.swift
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


// MARK: - Test Certificates -

struct TestCertificates {
    
    // grandcentrix certificates
    static let gcxRootCA = TestCertificates.certificate(name: "gcx-TrustedRoot")
    static let gcxIntermediateCA = TestCertificates.certificate(name: "gcx-DigiCertCA")
    static let gcxLeafWildcard = TestCertificates.certificate(name: "gcx-wildcard-valid")
    
    // grandcentrix self-signed and invalid certificates
    static let gcxSelfSignedExpired = TestCertificates.certificate(name: "gcx-selfsigned-expired")
    static let gcxSelfSignedValid = TestCertificates.certificate(name: "gcx-selfsigned-valid")
    static let invalidFile = TestCertificates.certificate(name: "invalidCertFile")
    static let gcxLeafWildcardExpired = TestCertificates.certificate(name: "gcx-wildcard-expired")
    
    // Disig test certificates http://testssl-expire.disig.sk/index.en.html
    static let disigRootCA = TestCertificates.certificate(name: "CA Disig Root R2")
    static let disigIntermediateCA = TestCertificates.certificate(name: "CA Disig R2I2 Certification Service")
    static let disigLeafValid = TestCertificates.certificate(name: "testssl-valid-r2i2.disig.sk")
    static let disigLeafExpired = TestCertificates.certificate(name: "testssl-expire-r2i2.disig.sk")
    static let disigLeafRevoked = TestCertificates.certificate(name: "testssl-revoked-r2i2.disig.sk")
    
    static func certificate(name fileName: String) -> SecCertificate {
        class Bundle {}
        let filePath = Foundation.Bundle(for: Bundle.self).path(forResource: fileName, ofType: "cer")!
        let data = try! Data(contentsOf: URL(fileURLWithPath: filePath))
        return SecCertificateCreateWithData(nil, data as CFData)!
    }
}

// MARK: - Test Trusts -

enum TestTrusts {
    
    case validGCXTrustChain
    case expiredGCXTrustChain
    case validGCXIntermediateAndRootOnly
    case validGCXWildcardOnly
    case validGCXRootOnly
    
    case validGCXSelfSigned
    case expiredGCXSelfSigned
    
    case validDisigTrustChain
    case expiredDisigTrustChain
    case revokedDisigTrustChain
    
    var trust: SecTrust {
        let trust: SecTrust
        
        switch self {
        
        case .validGCXTrustChain:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.gcxLeafWildcard,
                TestCertificates.gcxIntermediateCA,
                TestCertificates.gcxRootCA])
            
        case .expiredGCXTrustChain:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.gcxLeafWildcardExpired,
                TestCertificates.gcxIntermediateCA,
                TestCertificates.gcxRootCA])
            
        case .validGCXIntermediateAndRootOnly:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.gcxIntermediateCA,
                TestCertificates.gcxRootCA])
            
        case .validGCXWildcardOnly:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.gcxLeafWildcard])
            
        case .validGCXRootOnly:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.gcxRootCA])
            
        case .validGCXSelfSigned:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.gcxSelfSignedValid])
            
        case .expiredGCXSelfSigned:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.gcxSelfSignedExpired])
            
        case .validDisigTrustChain:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.disigLeafValid,
                TestCertificates.disigIntermediateCA,
                TestCertificates.disigRootCA])
            
        case .expiredDisigTrustChain:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.disigLeafExpired,
                TestCertificates.disigIntermediateCA,
                TestCertificates.disigRootCA])
            
        case .revokedDisigTrustChain:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.disigLeafRevoked,
                TestCertificates.disigIntermediateCA,
                TestCertificates.disigRootCA])
        }
        return trust
    }
    
    static func trustWithCertificates(_ certificates: [SecCertificate]) -> SecTrust {
        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        SecTrustCreateWithCertificates(certificates as CFTypeRef, policy, &trust)
        
        return trust!
    }
}
