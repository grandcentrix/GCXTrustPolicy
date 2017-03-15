//
//  ComposePolicyTests.swift
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

class ComposePolicyTests: XCTestCase {

    
    // MARK: - Variables -
    
    let testHost = "www.grandcentrix.net"
    
    var composal: ComposePolicy!
    var policy: TrustPolicy!
    var isValid: Bool!
    var trust: SecTrust!

    
    // MARK: - Disabled Validation -
    
    func test_disabledValidation_enabled_correctBehaviour() {
        
        composal = ComposePolicy(withValidation: .disabled, forHost: testHost)
        policy = composal.create()
        
        // true expectations
        trust = TestTrusts.validGCXTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Validation is disabled, must be valid.")
        
        trust = TestTrusts.expiredGCXSelfSigned.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Validation is disabled, must be valid.")
        
        trust = TestTrusts.expiredGCXTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Validation is disabled, must be valid.")
        
        trust = TestTrusts.revokedDisigTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Validation is disabled, must be valid.")
    }
    
    
    // MARK: - Custom Validation -
    
    func test_customValidation_enabled_correctBehaviour() {
        
        composal = ComposePolicy(withValidation: .custom, forHost: testHost)
        composal.customValidation = { trust -> Bool in
            return true
        }
        policy = composal.create()
        
        // true expectations
        trust = TestTrusts.validGCXTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Custom validation returns with true, must be valid.")
        
        trust = TestTrusts.expiredGCXTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Custom validation returns with true, must be valid.")
        
        trust = TestTrusts.validDisigTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Custom validation returns with true, must be valid.")
        
        trust = TestTrusts.revokedDisigTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Custom validation returns with true, must be valid.")
    }
    

    // MARK: - Default Validation -
    
    func test_defaultValidation_disabledHostValidation_correctBehaviour() {
    
        composal = ComposePolicy(withValidation: .standard, forHost: testHost)
        composal.validateHostName = false
        policy = composal.create()
        
        // true expectations
        trust = TestTrusts.validGCXTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Should be valid for certificate chain with valid host name.")
        
        trust = TestTrusts.validGCXWildcardOnly.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Should be valid for certificate chain with valid host name.")
        
        trust = TestTrusts.validGCXIntermediateAndRootOnly.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Should also be valid for intermediate and root as there is no host name.")
        
        trust = TestTrusts.validGCXRootOnly.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Should also be valid for rootas there is no host name.")
        
     
        // false expectations
        trust = TestTrusts.expiredGCXTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
        
        trust = TestTrusts.expiredDisigTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
        
        trust = TestTrusts.expiredDisigTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
        
        trust = TestTrusts.revokedDisigTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
        
        trust = TestTrusts.expiredGCXSelfSigned.trust
        isValid = policy.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
        
        trust = TestTrusts.validGCXSelfSigned.trust
        isValid = policy.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
    }

    func test_defaultValidation_enabledHostValidation_correctBehaviour() {
        
        composal = ComposePolicy(withValidation: .standard, forHost: testHost)
        composal.validateHostName = true // default setting
        policy = composal.create()
        
        
        // true expectations
        trust = TestTrusts.validGCXTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Should be valid for certificate chain with valid host name.")
        
        trust = TestTrusts.validGCXWildcardOnly.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Should be valid for leaf certificate.")
        
        
        // false expectations that depend on host name validation
        trust = TestTrusts.validDisigTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid with hostname validation.")
        
        trust = TestTrusts.validGCXIntermediateAndRootOnly.trust
        isValid = policy.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid with hostname validation.")
        
        trust = TestTrusts.validGCXRootOnly.trust
        isValid = policy.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid with hostname validation.")
        
        
        // false expectations
        trust = TestTrusts.expiredGCXTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
        
        trust = TestTrusts.expiredDisigTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
        
        trust = TestTrusts.expiredDisigTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
        
        trust = TestTrusts.revokedDisigTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
        
        trust = TestTrusts.expiredGCXSelfSigned.trust
        isValid = policy.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
        
        trust = TestTrusts.validGCXSelfSigned.trust
        isValid = policy.validate(with: trust)
        XCTAssertFalse(isValid, "Should be invalid.")
    }
    
    
    // MARK: - Certificate Pinning Validation -
    
    func test_certPinningValidation_allowInsecureServerTrust_correctBehaviour() {
        
        // take all certificates from test bundle into account for pinning match
        composal = ComposePolicy(withValidation: .pinCertificate, forHost: testHost)
        composal.certificateBundle = Bundle(for:ComposePolicyTests.self)
        composal.allowInsecureServerTrust = true
        policy = composal.create()
        
        // invalid certificates that would fail with enabled checking
        trust = TestTrusts.validGCXSelfSigned.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Should be valid as only pinning related checks are done.")
        
        trust = TestTrusts.expiredGCXSelfSigned.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Should be valid because only pinning related checks are done.")
        
        trust = TestTrusts.revokedDisigTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Should be valid as only pinning related checks are done.")
        
        trust = TestTrusts.expiredGCXTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Should be valid as only pinning related checks are done.")
    }
    
    
    // MARK: - Public Key Pinning Validation -
    
    func test_publicKeyPinningValidation_allowInsecureServerTrust_correctBehaviour() {
        
        // take all publlic keys from test bundle into account for pinning match
        composal = ComposePolicy(withValidation: .pinPublicKey, forHost: testHost)
        composal.certificateBundle = Bundle(for:ComposePolicyTests.self)
        composal.allowInsecureServerTrust = true
        policy = composal.create()
        
        // invalid certificates that would fail with enabled checking
        trust = TestTrusts.validGCXSelfSigned.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Should be valid as only pinning related checks are done.")
        
        trust = TestTrusts.expiredGCXSelfSigned.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Should be valid as only pinning related checks are done.")
        
        trust = TestTrusts.revokedDisigTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Should be valid as only pinning related checks are done.")
        
        trust = TestTrusts.expiredGCXTrustChain.trust
        isValid = policy.validate(with: trust)
        XCTAssertTrue(isValid, "Should be valid as only pinning related checks are done.")
    }
}
