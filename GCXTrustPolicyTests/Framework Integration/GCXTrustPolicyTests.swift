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

    func test_integration_swift_shouldWorkFlawlessWithFramework() {
        let defaultPolicy = ComposePolicy(withValidation: .standard, forHost: "hostNameA").create()
        let disabledPolicy = ComposePolicy(withValidation: .disabled, forHost: "hostNameB").create()
        
        let customPolicyComposal = ComposePolicy(withValidation: .custom, forHost: "hostNameC")
        customPolicyComposal.customValidation = { trust -> Bool in
            return true
        }
        let customPolicy = customPolicyComposal.create()
        
        let trustPolicies = [defaultPolicy, disabledPolicy, customPolicy]
        let manager = TrustManager(with: trustPolicies)
        let trust = TestTrusts.validGCXTrustChain.trust
        
        let policyHostNameA = manager.policy(for: "hostNameA")
        XCTAssertTrue(defaultPolicy === policyHostNameA!, "Objects should be equal.")
        var isTrusted = policyHostNameA!.validate(with: trust)
        XCTAssertFalse(isTrusted, "That should fail in every condition as there is no valid trust object.")
        
        let policyHostNameB = manager.policy(for: "hostNameB")
        XCTAssertTrue(disabledPolicy === policyHostNameB!, "Objects should be equal.")
        isTrusted = policyHostNameB!.validate(with: trust)
        XCTAssertTrue(isTrusted, "Disabled validation always returns TRUE regardless of all input.")
        
        let policyHostNameC = manager.policy(for: "hostNameC")
        XCTAssertTrue(customPolicy === policyHostNameC!, "Objects should be equal.")
        isTrusted = policyHostNameC!.validate(with: trust)
        XCTAssertTrue(isTrusted, "We previously defined cusom validation to return TRUE, so it should succeed.")
    }
}
