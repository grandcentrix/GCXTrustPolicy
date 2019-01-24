//
//  TrustPolicyBuilder.swift
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


////////////////////////////////////////////////
///
/// TrustPolicy building protocols.
///
////////////////////////////////////////////////

protocol TrustPolicyBuilding {
    var hostName: String { get set }
    func build() -> TrustDirective
}

protocol CustomTrustPolicyBuilding: TrustPolicyBuilding {
    var customValidation: ((_ trust: SecTrust?) -> Bool)! { get set }
}

protocol DefaultTrustPolicyBuilding: TrustPolicyBuilding {
    var validateHost: Bool! { get set }
    var allowInsecureTrust: Bool! { get set }
}

protocol PinTrustPolicyBuilding: DefaultTrustPolicyBuilding {
    var certificateBundle: Bundle! { get set }
}

protocol PinTrustOnlinePolicyBuilding: DefaultTrustPolicyBuilding {
    var trustServerCertificate: Data! { get set }
    var trustServer: URL! { get set }
    var customer: String! { get set }
}


////////////////////////////////////////////////
///
/// Concrete TrustPolicy builder classes
///
////////////////////////////////////////////////

///
/// Abstract base class. No direct instantiation intended.
///
class AbstractBuilder: TrustPolicyBuilding {
    
    var hostName: String
    
    init(withHostName host: String) {
        hostName = host
    }
    
    func build() -> TrustDirective {
        NSException(name: NSExceptionName(rawValue: "Unintended method call"),
                    reason: "Please use a concrete child class to perform object creation.",
                    userInfo: nil).raise()
        return DefaultDirective(withHostName: "", validateServerTrust: true, validateHost: true)
    }
}


///
/// Build a TrustDirective with disabled validation capabilities.
///
class DisabledBuilder: AbstractBuilder {
    
    override func build() -> TrustDirective {
        return DisabledDirective(withHostName: hostName)
    }
}


///
/// Build a TrustDirective with standard validation capabilities.
///
class DefaultBuilder: AbstractBuilder, DefaultTrustPolicyBuilding {
    
    var validateHost: Bool!
    var allowInsecureTrust: Bool!
    
    override func build() -> TrustDirective {
        return DefaultDirective(withHostName: hostName, validateServerTrust: !allowInsecureTrust, validateHost: validateHost)
    }
}


///
/// Build TrustDirective with custom validation capabilities.
///
class CustomBuilder: AbstractBuilder, CustomTrustPolicyBuilding {
    
    var customValidation: CustomValidationClosure!
    
    override func build() -> TrustDirective {
        return CustomDirective(withHostName: hostName, customValidation: customValidation)
    }
}


///
/// Build a TrustDirective with certificate pinning capabilities.
///
class CertificateBuilder: DefaultBuilder, PinTrustPolicyBuilding {
    
    var certificateBundle: Bundle!
    
    override func build() -> TrustDirective {
        return PinCertificateDirective(certificateBundle: certificateBundle, hostName: hostName, validateServerTrust: !allowInsecureTrust, validateHost: validateHost)
    }
}


///
/// Build a TrustDirective with public key pinning capabilities.
///
class PublicKeyBuilder: DefaultBuilder, PinTrustPolicyBuilding {
    
    var certificateBundle: Bundle!
    
    override func build() -> TrustDirective {
        return PinPublicKeyDirective(certificateBundle: certificateBundle, hostName: hostName, validateServerTrust: !allowInsecureTrust, validateHost: validateHost)
    }
}
