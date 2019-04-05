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
@testable import GCXTrustPolicy

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

        manager = TrustManager()
        policyA = manager.create(type: .disabled, hostName: hostA)
        policyB = manager.create(type: .standard, hostName: hostB)
        policyC = manager.create(type: .standard, hostName: hostC)
        trustPolicies = [policyA, policyB, policyC]
        manager.add(policies: trustPolicies)
    }
    
    override func tearDown() {
        manager = nil
        trustPolicies = nil
        
        super.tearDown()
    }

    // MARK: - TrustPolicyManager -
    
    func test_manager_initialisation_distinctInstanceAndSingleton() {
        
        manager = TrustManager()
        XCTAssertNotNil(manager, "Manager should not be nil.")
        XCTAssertTrue(manager.allPolicies.count == 0, "Should be initialized with empty TrustPolicies.")
        
        manager.add(policies: trustPolicies)
        XCTAssertTrue(manager.allPolicies.count == trustPolicies.count, "Should be initialized with 3 TrustPolicies.")
        
        manager = TrustManager.shared
        XCTAssertTrue(manager.allPolicies.count == 0, "Singleton should be initialized with empty TrustPolicies.")
    }
    
    func test_manager_policies_addRemove() {
        
        let policyNameA = manager.allNames.filter { $0 == hostA }.first!
        XCTAssertTrue(manager.allNames.count == 3, "Host name array should have length of 3.")
        XCTAssertTrue(policyNameA == hostA, "Host names should be equal.")
        
        let trustPolicyB = manager.allPolicies.filter { $0 === policyB }.first!
        XCTAssertTrue(manager.allPolicies.count == 3, "Policies array should have length of 3.")
        XCTAssertTrue(trustPolicyB === policyB, "Policies should be equal.")
        
        let policyNameC = manager.allNames.filter { $0 == hostC }
        let trustPolicyC = manager.policy(for: policyNameC.first!)
        XCTAssertNotNil(trustPolicyC, "Policy should not be nil.")
        XCTAssertTrue(trustPolicyC === policyC, "Policys should be equal.")
        
        let newPolicyHostName = "newPolicyHostName"
        let newPolicy = manager.create(type: .disabled, hostName: newPolicyHostName)
        manager.add(policy: newPolicy)
        XCTAssertTrue(manager.allPolicies.count == 4, "Policies array should have length of 4.")
        
        let removedPolicy = manager.removePolicy(name: newPolicyHostName)
        XCTAssertNotNil(removedPolicy)
        XCTAssertTrue(manager.allPolicies.count == 3, "Policies array should have length of 3.")
        
        manager.removePolicy(name: hostA)
        manager.removePolicy(name: hostB)
        manager.removePolicy(name: hostC)
        
        XCTAssertTrue(manager.allNames.count == 0, "Host name array should have length of 0.")
        XCTAssertTrue(manager.allPolicies.count == 0, "Policies array should have length of 0.")
    }

    func test_manager_noPolicies_correctBehaviour() {
        
        XCTAssertTrue(manager.allNames.count == 3, "Host name array should have length of 3.")
        
        let policy = manager.policy(for: "")
        XCTAssertNil(policy, "Policy should be nil.")
    }
}
