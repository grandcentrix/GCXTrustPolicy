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
    
    open var policies: [String : TrustPolicy] {
        get { return _policies }
        set { _policies = newValue }
    }
    
    open var allPolicies: [TrustPolicy] {
        return Array(policies.values)
    }
    
    open var allNames: [String] {
        return Array(policies.keys)
    }
    
    open func create(type: ValidationType, hostName: String, settings: ValidationSettings? = nil) -> TrustPolicy {
        let settings = settings ?? ValidationSettings.defaultSettings

        switch type {
        case .disabled:
            return DisabledDirective(hostName: hostName, settings: settings)
            
        case .standard:
            return DefaultDirective(hostName: hostName, settings: settings)
            
        case .custom:
            return CustomDirective(hostName: hostName, settings: settings)
            
        case .pinCertificate:
            return PinCertificateDirective(hostName: hostName, settings: settings)
            
        case .pinPublicKey:
            return PinPublicKeyDirective(hostName: hostName, settings: settings)
        }
    }
    
    open func policy(for name: String) -> TrustPolicy? {
        return policies[name]
    }
    
    open func add(policy: TrustPolicy) {
        policies[policy.hostName] = policy
    }
    
    open func add(policies: [TrustPolicy]) {
        for item in policies {
            add(policy: item)
        }
    }
    
    @discardableResult
    open func removePolicy(name: String) -> TrustPolicy? {
        return policies.removeValue(forKey: name)
    }
}

@objc(GCXValidationSettings)
open class ValidationSettings: NSObject, ValidationCustomizable {

    /// Convenience settings that contain an object with default values.
    @objc public static var defaultSettings: ValidationSettings {
        return ValidationSettings()
    }

    open var sslValidateHostName: Bool = true
    
    open var certificateBundle: Bundle = Bundle.main
    
    open var certificatePinOnly: Bool = false
    
    open var customValidation: CustomValidationClosure? = nil
}
