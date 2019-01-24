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
open class TrustManager: NSObject {

    /// Shared instance to the `TrustManager` object to use
    /// this class as Singleton.
    @objc public static let shared = TrustManager()
    
    /// Dictionary of `TrustPolicy`s.
    /// It is intended to use the host's name as key.
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
    
    /// Retrieve matching policy by host name.
    ///
    /// - Parameter hostName: the name of the host
    /// - Returns: optional TrustPolicy conforming object
    @objc open func policy(for hostName: String) -> TrustPolicy? {
        return policies[hostName]
    }
    
    /// Retrieve all registered host names.
    ///
    /// - Returns: Array of host names
    @objc open func allHostNames() -> [String] {
        return Array(policies.keys)
    }

    /// Retrieve all registered `TrustPolicy` objects.
    ///
    /// - Returns: Array of `TrustPolicy` conforming objects
    @objc open func allPolicies() -> [TrustPolicy] {
        return Array(policies.values)
    }

    /// Adds a new `TrustPolicy` object.
    ///
    /// - Parameter trustPolicy: `TrustPolicy` conforming object
    @objc open func add(policy trustPolicy: TrustPolicy) {
        policies[trustPolicy.hostName] = trustPolicy
    }
    
    /// Adds a batch of `TrustPolicy` objects at once.
    ///
    /// - Parameter trustPolicies: Array of `TrustPolicy` conforming objects
    @objc open func add(policies trustPolicies: [TrustPolicy]) {
        for item in trustPolicies {
            add(policy: item)
        }
    }
    
    /// Remove a TrustPolicy object by it`s key.
    ///
    /// - Parameter hostName: a host name
    @objc open func removePolicy(for hostName: String) {
        policies.removeValue(forKey: hostName)
    }
}
