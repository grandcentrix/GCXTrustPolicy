//
//  TrustDirectivePinPublicKeyTests.swift
//  GCXSSLPinning
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


import XCTest

@testable
import GCXTrustPolicy

class TrustDirectivePinPublicKeyTests: XCTestCase {
    /*
    
    // MARK: - Variables -
    
    var isValid: Bool!
    var directive: PinPublicKeyDirective!
    var trust: SecTrust!
    var publicKeys: [SecKey]!
    var testHost: String!
    let dummyBundle = Bundle(for:TrustDirectivePinPublicKeyTests.self)
    
    
    // MARK: - Valid trust chain tests -
    
    func test_validCertificatePinnedKey_validTrustChain_gotApproved () {
        
        // wildcard *.grandcentrix leaf certifcate incl. complete chain
        trust = TestTrusts.validGCXTrustChain.trust
        testHost = "grandcentrix.net"
        
        publicKeys = [TrustEvaluation.publicKey(from: TestCertificates.gcxLeafWildcard)!]
        directive = PinPublicKeyDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: true)
        directive.pinnedPublicKeys = publicKeys
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should succeed.")
        
        publicKeys = [TrustEvaluation.publicKey(from: TestCertificates.gcxIntermediateCA)!]
        directive = PinPublicKeyDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: true)
        directive.pinnedPublicKeys = publicKeys
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should succeed.")
        
        publicKeys = [TrustEvaluation.publicKey(from: TestCertificates.gcxRootCA)!]
        directive = PinPublicKeyDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: true)
        directive.pinnedPublicKeys = publicKeys
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should succeed.")
        
        
/*
 Note: The valid Disig Test certificate has been expired in 11/2016 and has not been renewed yet.
 Now the tests fail (which is correct) but for a clear understanding of the testing setup we uncomment them for now.
 */
        
//        // disig leaf certifcate incl. complete chain
//        trust = TestTrusts.validDisigTrustChain.trust
//        testHost =  "testssl-valid-r2i2.disig.sk"
//        
//        publicKeys = [TrustEvaluation.publicKey(from: TestCertificates.disigLeafValid)!]
//        directive = PinPublicKeyDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: true)
//        directive.pinnedPublicKeys = publicKeys
//        isValid = directive.validate(with: trust)
//        XCTAssertTrue(isValid, "Validation should succeed.")
//        
//        publicKeys = [TrustEvaluation.publicKey(from: TestCertificates.disigIntermediateCA)!]
//        directive = PinPublicKeyDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: true)
//        directive.pinnedPublicKeys = publicKeys
//        isValid = directive.validate(with: trust)
//        XCTAssertTrue(isValid, "Validation should succeed.")
//        
//        publicKeys = [TrustEvaluation.publicKey(from: TestCertificates.disigRootCA)!]
//        directive = PinPublicKeyDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: true)
//        directive.pinnedPublicKeys = publicKeys
//        isValid = directive.validate(with: trust)
//        XCTAssertTrue(isValid, "Validation should succeed.")
    }

    
    // MARK: - Expired trust chain tests -
    
    func test_expiredCertificatePinnedKey_expiredTrustChain_gotApproved () {
        
        // securepush leaf certifcate incl. complete chain
        trust = TestTrusts.expiredGCXTrustChain.trust
        testHost = "api.securepush.de"
        
        publicKeys = [TrustEvaluation.publicKey(from: TestCertificates.gcxLeafWildcardExpired)!]
        directive = PinPublicKeyDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: true)
        directive.pinnedPublicKeys = publicKeys
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
        
        publicKeys = [TrustEvaluation.publicKey(from: TestCertificates.gcxLeafWildcardExpired)!]
        directive = PinPublicKeyDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: true)
        directive.pinnedPublicKeys = publicKeys
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
        
        publicKeys = [TrustEvaluation.publicKey(from: TestCertificates.gcxIntermediateCA)!]
        directive = PinPublicKeyDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: true)
        directive.pinnedPublicKeys = publicKeys
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
        
        publicKeys = [TrustEvaluation.publicKey(from: TestCertificates.gcxRootCA)!]
        directive = PinPublicKeyDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: true)
        directive.pinnedPublicKeys = publicKeys
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
    }
    
    func test_expiredCertificatePinnedKey_expiredTrustChain_gotRejected () {
        
        // securepush leaf certifcate incl. complete chain
        trust = TestTrusts.expiredGCXTrustChain.trust
        testHost = "api.securepush.de"
        
        publicKeys = [TrustEvaluation.publicKey(from: TestCertificates.gcxLeafWildcardExpired)!]
        directive = PinPublicKeyDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: false, validateHost: true)
        directive.pinnedPublicKeys = publicKeys
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should only succeed on disabled X.509 standard checks.")
        
        // disig expired leaf certifcate incl. complete chain
        trust = TestTrusts.expiredDisigTrustChain.trust
        testHost = "testssl-expire-r2i2.disig.sk"

        publicKeys = [TrustEvaluation.publicKey(from: TestCertificates.disigLeafExpired)!]
        directive = PinPublicKeyDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: false, validateHost: false)
        directive.pinnedPublicKeys = publicKeys
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should only succeed on disabled X.509 standard checks.")
    }

    
    // MARK: - Revoked trust chain tests -
    
    func test_revokedCertificatePinnedKey_revokedTrustChain_gotRejected () {
        
        // disig revoked leaf certifcate incl. complete chain
        trust = TestTrusts.revokedDisigTrustChain.trust
        testHost =  "testssl-revoked-r2i2.disig.sk"
        
        publicKeys = [TrustEvaluation.publicKey(from: TestCertificates.disigLeafRevoked)!]
        directive = PinPublicKeyDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: true)
        directive.pinnedPublicKeys = publicKeys
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
    }
    
    func test_revokedCertificatePinnedKey_revokedTrustChainWithoutValidation_gotApproved () {
        
        // disig revoked leaf certifcate incl. complete chain
        trust = TestTrusts.revokedDisigTrustChain.trust
        testHost =  "testssl-revoked-r2i2.disig.sk"
        
        publicKeys = [TrustEvaluation.publicKey(from: TestCertificates.disigLeafRevoked)!]
        directive = PinPublicKeyDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: false, validateHost: false)
        directive.pinnedPublicKeys = publicKeys
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should only succeed on disabled X.509 standard checks.")
    }
 */
}
