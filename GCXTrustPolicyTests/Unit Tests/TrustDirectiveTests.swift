//
//  TrustDirectiveTests.swift
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

class TrustDirectiveTests: XCTestCase {
    
    // MARK: - Variables -
    
    var trust: SecTrust!
    var isValid: Bool!
    var testBundle = Bundle(for: TrustDirectiveTests.self)
    var testHost = "grandcentrix.net"
    var settings = ValidationSettings.defaultSettings
    var directive: AbstractDirective!
    
    // MARK: - Discarding of invalid certificates -
    
    func test_certificateLoading_fromTestBundle_invalidCertificatesSkipped() {
        
        let localCertificates = [
            "CA Disig Root R2",
            "CA Disig R2I2 Certification Service",
            "testssl-valid-r2i2.disig.sk",
            "testssl-expire-r2i2.disig.sk",
            "testssl-revoked-r2i2.disig.sk",
            "invalidCertFile",
            "gcx-TrustedRoot",
            "gcx-DigiCertCA",
            "gcx-wildcard-valid",
            "gcx-wildcard-expired",
            "gcx-selfsigned-expired",
            "gcx-selfsigned-valid"]
        
        let loadedCertificatesCount = localCertificates
            .map {
                let fileURL = testBundle.url(forResource: $0 as String, withExtension: "cer")
                XCTAssertNotNil(fileURL, "File URLs should be valid.")
            }
            .count
        
        let validLocalCertificatesCount = loadedCertificatesCount - 1 // randomGibberish.cer is expected as invalid
        let certificatesCount = TrustEvaluation.readDERCertificates(in: testBundle).count
        let hasEqualCount = certificatesCount == validLocalCertificatesCount
        
        XCTAssertTrue(hasEqualCount, "Certificate count should match the count of valid certificates.")
    }
    
    // MARK: - Disabled validation -

    func test_disableValidation_forAllTrusts_successful() {
        
        directive = DisabledDirective(hostName: testHost, settings: ValidationSettings.defaultSettings)
        
        // true expectations
        trust = TestTrusts.validGCXTrustChain.trust
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Disabled directive should return with true.")
        
        trust = TestTrusts.expiredGCXTrustChain.trust
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Disabled directive should return with true.")
        
        trust = TestTrusts.validDisigTrustChain.trust
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Disabled directive should return with true.")
        
        trust = TestTrusts.expiredDisigTrustChain.trust
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Disabled directive should return with true.")
        
        trust = TestTrusts.expiredGCXSelfSigned.trust
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Disabled directive should return with true.")
    }
    
    // MARK: - Default validation -

    func test_defaultDirective_withHostNameValidation_successfulForValidTrusts() {
        
        directive = DefaultDirective(hostName: testHost, settings: ValidationSettings.defaultSettings)
        
        // true expectations
        trust = TestTrusts.validGCXTrustChain.trust
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Should be valid for certificate chain.")
        
        trust = TestTrusts.validGCXWildcardOnly.trust
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Should be valid for leaf certificate.")
        
        // false expectations
        trust = TestTrusts.validGCXIntermediateAndRootOnly.trust
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Should be invalid for intermediate and anchor certificate.")
        
        trust = TestTrusts.validGCXRootOnly.trust
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Should be invalid for anchor certificate.")
        
        trust = TestTrusts.expiredGCXSelfSigned.trust
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
        
        trust = TestTrusts.validGCXSelfSigned.trust
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
    }
    
    func test_defaultDirective_noHostNameValidation_successfulForValidTrusts() {
        let settings = ValidationSettings.defaultSettings
        settings.sslValidateHostName = false
        directive = DefaultDirective(hostName: testHost, settings: settings)
        
        // true expectations
        trust = TestTrusts.validGCXTrustChain.trust
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Should be valid for certificate chain.")
        
        trust = TestTrusts.validGCXWildcardOnly.trust
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Should be valid for leaf certificate.")
        
        trust = TestTrusts.validGCXIntermediateAndRootOnly.trust
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Should be invalid for intermediate and anchor certificate.")
        
        trust = TestTrusts.validGCXRootOnly.trust
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Should be valid for anchor certificate.")

        // false expectations
        trust = TestTrusts.validGCXSelfSigned.trust
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
        
        trust = TestTrusts.expiredGCXSelfSigned.trust
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
    }
    
    // MARK: - Custom validation -
    
    func test_customValidation_correct_dependingOnClosureReturn() {

        // true expectations
        settings.customValidation = { trust -> Bool in
            return true
        }
        directive = CustomDirective(hostName: testHost, settings: settings)
        
        trust = TestTrusts.validGCXTrustChain.trust
        isValid = directive.validate(trust: trust)
        XCTAssertTrue(isValid, "Custom directive should return with true.")
        
        
        // false expectations
        settings.customValidation = { trust -> Bool in
            return false
        }
        directive = CustomDirective(hostName: testHost, settings: settings)
        
        trust = TestTrusts.validGCXTrustChain.trust
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Custom directive should return with false.")
    }
    
    func test_customValidation_missingValidationClosure_validationFails() {
        
        directive = CustomDirective(hostName: testHost, settings: settings)
        
        trust = TestTrusts.validGCXTrustChain.trust
        isValid = directive.validate(trust: trust)
        XCTAssertFalse(isValid, "Validate on a custom directive with missing closure must return false.")
    }
}
