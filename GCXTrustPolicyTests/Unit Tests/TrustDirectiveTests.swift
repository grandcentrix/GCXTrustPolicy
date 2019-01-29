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
/*
    
    // MARK: - Variables -
    var trust: SecTrust!
    var isValid:Bool!
    var testBundle = Bundle(for:TrustDirectiveTests.self)
    var testHost = "grandcentrix.net"


    // MARK: - Discarding of invalid certificates -
    
    func test_validation_certificateLoadingFromTestBundle_invalidCertificatesSkipped() {
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
        
        let loadedCertificatesCount = localCertificates.map {
            let fileURL = testBundle.url(forResource: $0 as String, withExtension: "cer")
            XCTAssertNotNil(fileURL, "File URLs should be valid.")
            }.count
        let validLocalCertificatesCount = loadedCertificatesCount - 1 // randomGibberish.cer is expected as invalid
        let certificatesCount = TrustEvaluation.readDERCertificates(in: testBundle).count
        let hasEqualCount = certificatesCount == validLocalCertificatesCount
        
        XCTAssertTrue(hasEqualCount, "Certificate count should match the count of valid certificates.")
    }

    
    // MARK: - Disabled validation -
    
    func test_validation_disableValidation_successfulForAllTrusts() {
        let validation = DisabledDirective(withHostName: testHost)
        
        // true expectations
        trust = TestTrusts.validGCXTrustChain.trust
        isValid = validation.validate(with: trust)
        XCTAssertTrue(isValid, "Disabled validation should return with true.")
        
        trust = TestTrusts.expiredGCXTrustChain.trust
        isValid = validation.validate(with: trust)
        XCTAssertTrue(isValid, "Disabled validation should return with true.")
        
        trust = TestTrusts.validDisigTrustChain.trust
        isValid = validation.validate(with: trust)
        XCTAssertTrue(isValid, "Disabled validation should return with true.")
        
        trust = TestTrusts.expiredDisigTrustChain.trust
        isValid = validation.validate(with: trust)
        XCTAssertTrue(isValid, "Disabled validation should return with true.")
        
        trust = TestTrusts.expiredGCXSelfSigned.trust
        isValid = validation.validate(with: trust)
        XCTAssertTrue(isValid, "Disabled validation should return with true.")
    }
    
    
    // MARK: - Standard validation -
    
    func test_validation_standardWithHostNameValidation_successfulForValidTrusts() {
        
        let validation = DefaultDirective(withHostName: testHost, validateServerTrust: true, validateHost: true)
        
        // true expectations
        trust = TestTrusts.validGCXTrustChain.trust
        isValid = validation.validate(with: trust)
        XCTAssertTrue(isValid, "Should be valid for certificate chain.")
        
        trust = TestTrusts.validGCXWildcardOnly.trust
        isValid = validation.validate(with: trust)
        XCTAssertTrue(isValid, "Should be valid for leaf certificate.")
        
        // false expectations
        trust = TestTrusts.validGCXIntermediateAndRootOnly.trust
        isValid = validation.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid for intermediate and anchor certificate with hostname validation.")
        
        trust = TestTrusts.validGCXRootOnly.trust
        isValid = validation.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid for anchor certificate with hostname validation.")
        
        trust = TestTrusts.expiredGCXSelfSigned.trust
        isValid = validation.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
        
        trust = TestTrusts.validGCXSelfSigned.trust
        isValid = validation.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
    }
    
    func test_validation_standardNoHostNameValidation_successfulForValidTrusts() {
    
        let validation = DefaultDirective(withHostName: testHost, validateServerTrust: true, validateHost: false)
        
        // true expectations
        trust = TestTrusts.validGCXTrustChain.trust
        isValid = validation.validate(with: trust)
        XCTAssertTrue(isValid, "Should be valid for certificate chain.")
        
        trust = TestTrusts.validGCXWildcardOnly.trust
        isValid = validation.validate(with: trust)
        XCTAssertTrue(isValid, "Should be valid for leaf certificate.")
        
        trust = TestTrusts.validGCXWildcardOnly.trust
        isValid = validation.validate(with: trust)
        XCTAssertTrue(isValid, "Should be valid for stripped down chain.")
        
        trust = TestTrusts.validGCXRootOnly.trust
        isValid = validation.validate(with: trust)
        XCTAssertTrue(isValid, "Should be valid for anchor certificate.")
        
        
        
// TODO: that should work
        // false expectations
        trust = TestTrusts.validGCXSelfSigned.trust
        isValid = validation.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
        
        trust = TestTrusts.expiredGCXSelfSigned.trust
        isValid = validation.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
    }
    

    // MARK: - Custom validation -
    
    func test_validation_customValidation_successfulDependingOnReturnValue() {
        var closure: CustomValidationClosure!
        var validation: CustomDirective!
            
        // true expectations
        closure = { trust -> Bool in
            // do some custom validation based on the given trust
            return true
        }
        validation = CustomDirective(withHostName: testHost, customValidation: closure)
        
        trust = TestTrusts.validGCXTrustChain.trust
        isValid = validation.validate(with: trust)
        XCTAssertTrue(isValid, "Custom validation should return with true.")
        
        
        // false expectations
        closure = { trust -> Bool in
            // do some custom validation based on the given trust
            return false
        }
        validation = CustomDirective(withHostName: testHost, customValidation: closure)
        
        trust = TestTrusts.validGCXTrustChain.trust
        isValid = validation.validate(with: trust)
        XCTAssertFalse(isValid, "Custom validation should return with false.")
    }
 */
}
