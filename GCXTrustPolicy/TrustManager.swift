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
    
    /// Trust policies to manage
    private var _policies: [String: TrustPolicy] = [:]
}

/// TrustManaging protocol implementation
@objc extension TrustManager: TrustManaging {
    
    public var policies: [String : TrustPolicy] {
        get {
            return _policies
        }
        set {
            _policies = newValue
        }
    }
    
    public var allPolicies: [TrustPolicy] {
        return Array(policies.values)
    }
    
    public var allNames: [String] {
        return Array(policies.keys)
    }
    
    public func create(type: ValidationType, hostName: String?, certificateBundle: Bundle = Bundle.main, customValidation: CustomValidationClosure? = nil) -> TrustPolicy {
        
        switch type {
        case .disabled:
            return DisabledDirective(hostName: hostName)
            
        case .standard:
            return DefaultDirective(hostName: hostName)
            
        case .custom:
            if customValidation == nil {
                let name = NSExceptionName(rawValue: "Missing Parameter")
                let reason = "Please provide a custom validation closure."
                NSException(name: name, reason: reason, userInfo: nil).raise()
            }
            return CustomDirective(hostName: hostName, customValidation: customValidation!)
            
        case .pinCertificate:
            return PinCertificateDirective( hostName: hostName, certificateBundle: certificateBundle)
            
        case .pinPublicKey:
            return PinPublicKeyDirective(hostName: hostName, certificateBundle: certificateBundle)
        }
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
    
    public func removePolicy(name: String) -> TrustPolicy? {
        return policies.removeValue(forKey: name)
    }
}
