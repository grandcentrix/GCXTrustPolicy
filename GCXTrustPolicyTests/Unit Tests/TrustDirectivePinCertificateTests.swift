//
//  TrustDirectivePinCertificateTests.swift
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


import XCTest

@testable
import GCXTrustPolicy

class TrustDirectivePinCertificateTests: XCTestCase {
    
    
    // MARK: - Variables -
    
    var isValid:Bool!
    var directive: PinCertificateDirective!
    let testHost = "grandcentrix.net"
    let dummyBundle = Bundle(for:TrustDirectivePinCertificateTests.self)
    

    // MARK: - Certificate Pinning -
    
    func test_validation_selfSignedVersusSelfSigned_correctBehaviour() {
        
        // local self-signed certificate
        // vs. remote self-signed certificate
        
        let localCertificate = [TestCertificates.gcxSelfSignedValid]
        let trust = TestTrusts.validGCXSelfSigned.trust
        
        
        // false expectations
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: true)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: false)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
        
        
        // true expectations
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: false, validateHost: true)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should succeed as we pin against the certificate without standard X.509 validation.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: false, validateHost: false)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should succeed as we pin against the certificate without standard X.509 validation.")
    }
    
    func test_validation_expiredSelfSignedVersusSelfSigned_correctBehaviour() {
        
        // local expired self-signed certificate
        // vs. remote self-signed certificate
        let localCertificate = [TestCertificates.gcxSelfSignedValid]
        let trust = TestTrusts.validGCXSelfSigned.trust
        
        
        // false expectations
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: true)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: false)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
        
        
        // true expectations
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: false, validateHost: true)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should succeed as we pin against the certificate without standard X.509 validation.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: false, validateHost: false)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should succeed as we pin against the certificate without standard X.509 validation.")
    }
    
    func test_validation_expiredSelfSignedVersusExpiredSelfSigned_correctBehaviour() {
        
        // local expired self-signed certificate
        // vs. remote expired self-signed certificate
        let localCertificate = [TestCertificates.gcxSelfSignedExpired]
        let trust = TestTrusts.expiredGCXSelfSigned.trust
        
        
        // false expectations
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: true)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: false)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
        
        
        // true expectations
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: false, validateHost: true)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should succeed as we pin against the certificate without standard X.509 validation.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: false, validateHost: false)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should succeed as we pin against the certificate without standard X.509 validation.")
    }
    
    func test_validation_selfSignedVersusValidLeafCertificat_gotRejected() {
        
        // local self-signed certificate
        // vs. remote valid leaf certificate
        let localCertificate = [TestCertificates.gcxSelfSignedValid]
        let trust = TestTrusts.validGCXWildcardOnly.trust
        
        
        // false expectations
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: true)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: false)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: false, validateHost: true)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: false, validateHost: false)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
    }
    
    func test_validation_selfSignedVersusValidTrustChain_gotRejected() {
        
        // local self-signed certificate
        // vs. remote trust chain
        let localCertificate = [TestCertificates.gcxSelfSignedValid]
        let trust = TestTrusts.validDisigTrustChain.trust
        
        
        // false expectations
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: true)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: false)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: false, validateHost: true)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: false, validateHost: false)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
    }
    
    func test_validation_leafVersusValidLeafCertificate_gotApproved() {
        
        // local leaf certificate 
        // vs. remote leaf certificate
        let localCertificate = [TestCertificates.gcxLeafWildcard]
        let trust = TestTrusts.validGCXWildcardOnly.trust
        
        
        // true expectations
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: true)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should succeed.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: false)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should succeed.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: false, validateHost: true)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should succeed.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: false, validateHost: false)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should succeed.")
    }
    
    func test_validation_validLeafVersusValidChain_gotRejected() {

        // local leaf certificate
        // vs. remote valid certificate chain
        let localCertificate = [TestCertificates.gcxLeafWildcard]
        let trust = TestTrusts.validDisigTrustChain.trust

        
        // false expectations
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: true)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: false)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: false, validateHost: true)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: false, validateHost: false)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        XCTAssertFalse(isValid, "Validation should not succeed.")
    }
    
    func test_validation_certificatePinning_validRootVersusValidChain_gotApproved() {
        
        // valid local root certificate
        // vs. remote valid certificate chain
        let localCertificate = [TestCertificates.gcxRootCA]
        let trust = TestTrusts.validGCXTrustChain.trust
        
        
        // true expectations
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: true)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should succeed.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: true, validateHost: false)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should succeed.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: false, validateHost: true)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should succeed.")
        
        directive = PinCertificateDirective(certificateBundle: dummyBundle, hostName: testHost, validateServerTrust: false, validateHost: false)
        directive.pinnedCertificateDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(with: trust)
        XCTAssertTrue(isValid, "Validation should succeed.")
    }
}
