//
//  TrustManager.swift
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

import Foundation

@objc(GCXTrustManager)
/// Class managing trust policies
open class TrustManager: NSObject {

    /// Shared instance to the `TrustManager` object to use
    /// this class as Singleton.
    @objc public static let shared = TrustManager()
    
    /// `Trusting` protocol implementation
    @objc open var policies: [String: TrustPolicy] = [:]
    
    /// Convenience initializer tha allows to pass an Array
    /// of `TrustPolicy`s upon initialisation.
    ///
    /// Which offers the opportunity to apply different trust
    /// evaluation policies on a per-host basis.
    /// E.g. host 1 uses certificate pinning, host 2 simple
    /// host validation and host 3 uses public key pinning.
    ///
    /// - Parameter trustPolicies: Array of `TrustPolicy` conforming objects
    @objc public convenience init (with policies: [TrustPolicy]) {
        self.init()
        
        add(policies: policies)
    }
}

/// TrustManaging protocol implementation
@objc extension TrustManager: TrustManaging {
    
    public var allPolicies: [TrustPolicy] {
        return Array(policies.values)
    }
    
    public var allNames: [String] {
        return Array(policies.keys)
    }
    
    public func policy(for name: String) -> TrustPolicy? {
        return policies[name]
    }
    
    public func add(policy: TrustPolicy) {
        policies[policy.hostName] = policy
    }
    
    public func add(policies: [TrustPolicy]) {
        for item in policies {
            add(policy: item)
        }
    }
    
    public func removePolicy(name: String) {
        policies.removeValue(forKey: name)
    }
}
