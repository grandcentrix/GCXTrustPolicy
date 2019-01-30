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
@testable import GCXTrustPolicy

class TrustDirectivePinCertificateTests: XCTestCase {
    
    // MARK: - Variables -
    
    var isValid: Bool!
    var directive: PinCertificateDirective!
    let testHost = "grandcentrix.net"
    let dummyBundle = Bundle(for: TrustDirectivePinCertificateTests.self)
    var settings: ValidationSettings!
    
    // MARK: - Setup -
    
    override func setUp() {
        super.setUp()
        
        settings = ValidationSettings.defaultSettings
        settings.certificateBundle = dummyBundle
    }
    

    // MARK: - local self-signed certificate vs. remote self-signed certificate -
    
    func test_defaultValidation_selfSignedVsSelfSigned_assumedInvalid() {

        let localCertificate = [TestCertificates.gcxSelfSignedValid]
        let trust = TestTrusts.validGCXSelfSigned.trust

        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
    }
    
    func test_disabledHostValidation_selfSignedVsSelfSigned_assumedInvalid() {
        
        settings.sslValidateHostName = false // pinning with disabled host name check

        let localCertificate = [TestCertificates.gcxSelfSignedValid]
        let trust = TestTrusts.validGCXSelfSigned.trust

        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
    }
    
    func test_disabledSSLCheck_selfSignedVsSelfSigned_assumedValid() {
        
        settings.certificatePinOnly = true // skip SSL checks, only compare certs
        
        let localCertificate = [TestCertificates.gcxSelfSignedValid]
        let trust = TestTrusts.validGCXSelfSigned.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Validation should succeed as we pin against the certificate without standard X.509 validation.")
    }
    
    // MARK: - local expired self-signed certificate vs. remote self-signed certificate -
    
    func test_defaultValidation_expiredSelfSignedVsSelfSigned_assumedInvalid() {
        
        let localCertificate = [TestCertificates.gcxSelfSignedValid]
        let trust = TestTrusts.validGCXSelfSigned.trust

        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
    }
    
    func test_disabledHostValidation_expiredSelfSignedVsSelfSigned_assumedInvalid() {
        
        settings.sslValidateHostName = false // pinning with disabled host name check
        
        let localCertificate = [TestCertificates.gcxSelfSignedValid]
        let trust = TestTrusts.validGCXSelfSigned.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
    }
    
    func test_disabledSSLCheck_expiredSelfSignedVsSelfSigned_assumedValid() {
        
        settings.certificatePinOnly = true // skip SSL checks, only compare certs
        
        let localCertificate = [TestCertificates.gcxSelfSignedValid]
        let trust = TestTrusts.validGCXSelfSigned.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Validation should succeed as we pin against the certificate without standard X.509 validation.")
    }
    
    // MARK: - local expired self-signed certificate vs. remote expired self-signed certificate -
        
    func test_defaultSetting_expiredSelfSignedVsExpiredSelfSigned_assumedInvalid() {
        
        let localCertificate = [TestCertificates.gcxSelfSignedExpired]
        let trust = TestTrusts.expiredGCXSelfSigned.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
    }
    
    func test_disabledHostValidation_expiredSelfSignedVsExpiredSelfSigned_assumedInvalid() {
        
        settings.sslValidateHostName = false // pinning with disabled host name check
        
        let localCertificate = [TestCertificates.gcxSelfSignedExpired]
        let trust = TestTrusts.expiredGCXSelfSigned.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Validation should succeed as we pin against the certificate without standard X.509 validation.")
    }
    
    func test_disabledSSLCheck_expiredSelfSignedVsExpiredSelfSigned_assumedValid() {
        
        settings.certificatePinOnly = true // skip SSL checks, only compare certs
        
        let localCertificate = [TestCertificates.gcxSelfSignedExpired]
        let trust = TestTrusts.expiredGCXSelfSigned.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Validation should succeed as we pin against the certificate without standard X.509 validation.")
    }
    
    // MARK: - local self-signed certificate vs. remote valid leaf certificate -
    
    func test_defaultSetting_selfSignedVsValidLeafCertificate_assumedInvalid() {
        
        let localCertificate = [TestCertificates.gcxSelfSignedValid]
        let trust = TestTrusts.validGCXWildcardOnly.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
    }
    
    func test_disabledHostValidation_selfSignedVsValidLeafCertificate_assumedInvalid() {
        
        settings.sslValidateHostName = false // pinning with disabled host name check
        
        let localCertificate = [TestCertificates.gcxSelfSignedValid]
        let trust = TestTrusts.validGCXWildcardOnly.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
    }
    
    func test_disabledSSLCheck_selfSignedVersusValidLeafCertificate_assumedInvalid() {
        
        settings.certificatePinOnly = true // skip SSL checks, only compare certs
        
        let localCertificate = [TestCertificates.gcxSelfSignedValid]
        let trust = TestTrusts.validGCXWildcardOnly.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
    }

    // MARK: - local self-signed certificate vs. remote trust chain -
    
    func test_defaultSetting_selfSignedVsValidTrustChain_assumedInvalid() {
        
        let localCertificate = [TestCertificates.gcxSelfSignedValid]
        let trust = TestTrusts.validDisigTrustChain.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
    }
    
    func test_disabledHostValidation_selfSignedVsValidTrustChain_assumedInvalid() {
        
        settings.sslValidateHostName = false // pinning with disabled host name check
        
        let localCertificate = [TestCertificates.gcxSelfSignedValid]
        let trust = TestTrusts.validDisigTrustChain.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
    }
    
    func test_disabledSSLCheck_selfSignedVsValidTrustChain_assumedInvalid() {
        
        settings.certificatePinOnly = true // skip SSL checks, only compare certs
        
        let localCertificate = [TestCertificates.gcxSelfSignedValid]
        let trust = TestTrusts.validDisigTrustChain.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
    }
    
    // MARK: - local leaf certificate vs. remote leaf certificate -
    
    func test_defaultSetting_validLeafVsValidLeafCertificate_assumedValid() {
        
        let localCertificate = [TestCertificates.gcxLeafWildcard]
        let trust = TestTrusts.validGCXWildcardOnly.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Validation should succeed.")
    }
    
    func test_disabledHostValidation_validLeafVsValidLeafCertificate_assumedValid() {
        
        settings.sslValidateHostName = false // pinning with disabled host name check
        
        let localCertificate = [TestCertificates.gcxLeafWildcard]
        let trust = TestTrusts.validGCXWildcardOnly.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Validation should succeed.")
    }
    
    func test_disabledSSLCheck_validLeafVsValidLeafCertificate_assumedValid() {
        
        settings.certificatePinOnly = true // skip SSL checks, only compare certs
        
        let localCertificate = [TestCertificates.gcxLeafWildcard]
        let trust = TestTrusts.validGCXWildcardOnly.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Validation should succeed.")
    }
    
    // MARK: - local leaf certificate vs. remote valid certificate chain -
    
    func test_defaultSetting_validLeafVsValidChain_assumedInvalid() {
        
        let localCertificate = [TestCertificates.gcxLeafWildcard]
        let trust = TestTrusts.validDisigTrustChain.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
    }
    
    func test_disabledHostValidation_validLeafVsValidChain_assumedInvalid() {
        
        settings.sslValidateHostName = false // pinning with disabled host name check
        
        let localCertificate = [TestCertificates.gcxLeafWildcard]
        let trust = TestTrusts.validDisigTrustChain.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
    }
    
    func test_disabledSSLCheck_validLeafVsValidChain_assumedInvalid() {
        
        settings.certificatePinOnly = true // skip SSL checks, only compare certs
        
        let localCertificate = [TestCertificates.gcxLeafWildcard]
        let trust = TestTrusts.validDisigTrustChain.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Validation should not succeed.")
    }
    
    // MARK: - valid local root certificate vs. remote valid certificate chain -
    
    func test_defaultSetting_validRootVsValidChain_assumedValid() {
        
        let localCertificate = [TestCertificates.gcxRootCA]
        let trust = TestTrusts.validGCXTrustChain.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Validation should succeed.")
    }
    
    func test_disabledHostValidation_validRootVsValidChain_assumedValid() {
        
        settings.sslValidateHostName = false // pinning with disabled host name check
        
        let localCertificate = [TestCertificates.gcxRootCA]
        let trust = TestTrusts.validGCXTrustChain.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Validation should succeed.")
    }
    
    func test_disabledSSLCheck_validRootVsValidChain_assumedValid() {
        
        settings.certificatePinOnly = true // skip SSL checks, only compare certs
        
        let localCertificate = [TestCertificates.gcxRootCA]
        let trust = TestTrusts.validGCXTrustChain.trust
        
        directive = PinCertificateDirective(hostName: testHost, settings: settings)
        directive.pinnedCertDatas = TrustEvaluation.certificateData(from: localCertificate)
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Validation should succeed.")
    }
}
