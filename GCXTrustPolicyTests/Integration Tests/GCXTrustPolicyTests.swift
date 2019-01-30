//
//  GCXTrustPolicyTests.swift
//  GCXTrustPolicyTests
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
import GCXTrustPolicy

class GCXTrustPolicyTests: XCTestCase {
    
    let testTrust = TestTrusts.validGCXTrustChain.trust // test trust

    func test_swift_createManageRetrieveValidate_works() {
        
        // Trust policy creation tests for each trust validation type
        let trustManager = TrustManager()
        
        let defaultPolicy = trustManager.create(type: .standard, hostName: "defaultHost")
        
        let pinCertificatePolicy = trustManager.create(type: .pinCertificate, hostName: "pinCertHost")
        
        let pinPublicKeyPolicy = trustManager.create(type: .pinPublicKey, hostName: "pinPubKey")
    
        let disabledPolicy = trustManager.create(type: .disabled, hostName: "disabledHost")
        
        let customPolicy = trustManager.create(type: .custom, hostName: "customHost", customValidation: { trust -> Bool in
            /* more sophistic validataion checks should go here... */
            return false
        })
        
        // Trust policy management tests
        XCTAssert(trustManager.allPolicies.count == 0)
        XCTAssert(trustManager.allNames.count == 0)
        
        let allCreatedPolicies = [defaultPolicy, pinCertificatePolicy, pinPublicKeyPolicy, disabledPolicy, customPolicy]
        let allNames = allCreatedPolicies.compactMap { $0.hostName }
        
        trustManager.add(policies: allCreatedPolicies)

        XCTAssert(trustManager.allPolicies.count == allCreatedPolicies.count)
        XCTAssert(trustManager.allNames.count == allNames.count)
        
        let removedPolicy = trustManager.removePolicy(name: "disabledHost")!
        
        XCTAssertFalse(trustManager.allPolicies.contains { $0 === removedPolicy }, "Policy should be removed from manager.")
        XCTAssert(trustManager.allPolicies.count == allCreatedPolicies.count - 1)
        XCTAssert(trustManager.allNames.count == allNames.count - 1)
        
        trustManager.add(policy: disabledPolicy)
        
        XCTAssert(trustManager.allPolicies.count == allCreatedPolicies.count)
        XCTAssert(trustManager.allNames.count == allNames.count)
        
       
        // Trust policy retrieval and validation tests
        let defaultHostPolicy = trustManager.policy(for: "defaultHost")!
        XCTAssert(defaultPolicy === defaultHostPolicy, "Objects should be equal.")
        var isTrusted = defaultHostPolicy.validate(trust: testTrust)
        XCTAssertFalse(isTrusted, "That should FAIL in every condition as the test trust here is no valid trust object.")
        
        let pinCertHostPolicy = trustManager.policy(for: "pinCertHost")!
        XCTAssert(pinCertificatePolicy === pinCertHostPolicy, "Objects should be equal.")
        isTrusted = pinCertHostPolicy.validate(trust: testTrust)
        XCTAssertFalse(isTrusted, "That should FAIL in every condition as the test trust here is no valid trust object.")
        
        let pinPubKeyPolicy = trustManager.policy(for: "pinPubKey")!
        XCTAssert(pinPubKeyPolicy === pinPubKeyPolicy, "Objects should be equal.")
        isTrusted = pinPubKeyPolicy.validate(trust: testTrust)
        XCTAssertFalse(isTrusted, "That should FAIL in every condition as the test trust here is no valid trust object.")
        
        let disabledHostPolicy = trustManager.policy(for: "disabledHost")!
        XCTAssert(disabledPolicy === disabledHostPolicy, "Objects should be equal.")
        isTrusted = disabledHostPolicy.validate(trust: testTrust)
        XCTAssertTrue(isTrusted, "That should SUCCEED because disabled validation always returns TRUE regardless of all input.")
        
        let customHostPolicy = trustManager.policy(for: "customHost")!
        XCTAssert(customPolicy === customHostPolicy, "Objects should be equal.")
        isTrusted = customHostPolicy.validate(trust: testTrust)
        XCTAssertFalse(isTrusted, "That should FAIL because we previously defined custom validation closure to return FALSE.")
    }
}
