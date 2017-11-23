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

    
    /// trust policies by hostname
    fileprivate var policies: [String: TrustPolicy] = [:]
    

    /**
      A shared instance to use from e.g. NSURLSession or NSURLConnection.
      Will call the default initializer -init().
     */
    @objc open static let sharedInstance = TrustManager()
    
    /**
      Convenience initializer for trust policies per host.
      This offers the opportunity to apply different trust
      evaluation policies on a per-host basis.
      e.g. host 1 uses certificate pinning, host 2 simple 
      host validation and host 3 uses public key pinning.
     
      - parameter trustPolicies: an Array containing TrustPolicy conforming objects
     
      - returns: the instance
     */
    @objc public convenience init (trustPolicies: [TrustPolicy]) {
        self.init()
        
        add(policies: trustPolicies)
    }
    
    
    /**
      Retrieve the matching policy per host.
     
      - parameter hostName: the name of the host
     
      - returns: a TrustPolicy conforming object
     */
    @objc open func policy(forHost hostName: String) -> TrustPolicy? {
        return policies[hostName]
    }
    

    /** 
      Retrieve all registered host names.
     
      - returns: an array of string
     */
    @objc open func allHostNames() -> [String] {
        return Array(policies.keys)
    }
    
    
    /**
        Retrieve all registered TrustPolicy objects.
     
        - returns: array of TrustPolicy conforming objects
     */
    @objc open func allPolicies() -> [TrustPolicy] {
        return Array(policies.values)
    }
    
    
    /**
      Add a new TrustPolicy object.
      Key is the TrustPolicy`s 'hostName' property.
     
      - parameter policy: a TrustPolicy conforming object
     */
    @objc open func add(policy trustPolicy: TrustPolicy) {
        policies[trustPolicy.hostName] = trustPolicy
    }
    
    
    /**
      Convenience function to add a batch of TrustPolicy objects.
      Key is the TrustPolicy`s 'hostName' property.
     
      - parameter policies: a TrustPolicy conforming object
     */
    @objc open func add(policies trustPolicies: [TrustPolicy]) {
        for item in trustPolicies {
            add(policy: item)
        }
    }
    
    
    /**
      Remove a TrustPolicy object by it`s key.
      Key is the TrustPolicy`s 'hostName' property
     
     - parameter hostName: a host name
     */
    @objc open func removePolicy(for hostName: String) {
        policies.removeValue(forKey: hostName)
    }
}
