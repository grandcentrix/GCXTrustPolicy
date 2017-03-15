//
//  TrustManagerTests.swift
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

class TrustManagerTests: XCTestCase {

    
    // MARK: - Variables -
    
    let hostA = "hostA"
    let hostB = "hostB"
    let hostC = "hostC"
    
    var manager: TrustManager!
    var trustPolicies: [TrustPolicy]!
    var policyA: TrustPolicy!
    var policyB: TrustPolicy!
    var policyC: TrustPolicy!
    
    // MARK: - Setup -
    
    override func setUp() {
        super.setUp()
        
        policyA = ComposePolicy(withValidation: .disabled, forHost: hostA).create()
        policyB = ComposePolicy(withValidation: .standard, forHost: hostB).create()
        policyC = ComposePolicy(withValidation: .standard, forHost: hostC).create()
        trustPolicies = [policyA, policyB, policyC]
        manager = TrustManager(trustPolicies: trustPolicies)
    }
    
    override func tearDown() {
        manager = nil
        trustPolicies = nil
        
        super.tearDown()
    }

    
    // MARK: - TrustPolicyManager -
    
    func test_manager_initialisation_correctBehaviour() {
        manager = TrustManager()
        XCTAssertNotNil(manager, "Manager should not be nil.")
        XCTAssertTrue(manager.allPolicies().count == 0, "Should be initialized with empty TrustPolicies.")
        
        manager = TrustManager(trustPolicies: trustPolicies)
        XCTAssertNotNil(manager, "Manager should not be nil.")
        XCTAssertTrue(manager.allPolicies().count == trustPolicies.count, "Should be initialized with 3 TrustPolicies.")
        
        manager = TrustManager.sharedInstance
        XCTAssertNotNil(manager, "Manager should not be nil.")
        XCTAssertTrue(manager.allPolicies().count == 0, "Singleton should be initialized with empty TrustPolicies.")
    }
    
    
    func test_manager_functionality_correctBehaviour() {

        let names = manager.allHostNames()
        let policyNameA = names.filter{$0 == hostA}.first!
        XCTAssertTrue(names.count == 3, "Host name array should have length of 3.")
        XCTAssertTrue(policyNameA == hostA, "Host names should be equal.")
        
        var policies = manager.allPolicies()
        let trustPolicyB = policies.filter{$0 === policyB}.first!
        XCTAssertTrue(policies.count == 3, "Policies array should have length of 3.")
        XCTAssertTrue(trustPolicyB === policyB, "Policies should be equal.")
        
        let policyNameC = names.filter{$0 == hostC}
        let trustPolicyC = manager.policy(forHost: policyNameC.first!)
        XCTAssertNotNil(trustPolicyC, "Policy should not be nil.")
        XCTAssertTrue(trustPolicyC === policyC, "Policys should be equal.")
        
        let newPolicyHostName = "newPolicyHostName"
        let newPolicy = ComposePolicy(withValidation: .disabled, forHost: newPolicyHostName).create()
        manager.add(policy: newPolicy)
        policies = manager.allPolicies()
        XCTAssertTrue(policies.count == 4, "Policies array should have length of 4.")
        
        manager.removePolicy(for: newPolicyHostName)
        policies = manager.allPolicies()
        XCTAssertTrue(policies.count == 3, "Policies array should have length of 3.")
    }
    
    func test_manager_noPolicies_correctBehaviour() {
        
        var names = manager.allHostNames()
        XCTAssertTrue(names.count == 3, "Host name array should have length of 3.")
        
        let policy = manager.policy(forHost: "")
        XCTAssertNil(policy, "Policy should be nil.")
        
        manager.removePolicy(for: hostA)
        manager.removePolicy(for: hostB)
        manager.removePolicy(for: hostC)
        
        names = manager.allHostNames()
        XCTAssertTrue(names.count == 0, "Host name array should have length of 0.")
        
        let policies = manager.allPolicies()
        XCTAssertTrue(policies.count == 0, "Policies array should have length of 0.")
    }
}
