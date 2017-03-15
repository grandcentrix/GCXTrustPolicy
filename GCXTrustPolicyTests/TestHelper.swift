//
//  TestHelper.swift
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


// MARK: - Test Certificates -

struct TestCertificates {
    
    // grandcentrix certificates
    static let gcxRootCA = TestCertificates.certificate(name: "gcx-TrustedRoot")
    static let gcxIntermediateCA = TestCertificates.certificate(name: "gcx-DigiCertCA")
    static let gcxLeafWildcard = TestCertificates.certificate(name: "gcx-wildcard-valid")
    
    // grandcentrix self-signed and invalid certificates
    static let gcxSelfSignedExpired = TestCertificates.certificate(name: "gcx-selfsigned-expired")
    static let gcxSelfSignedValid = TestCertificates.certificate(name: "gcx-selfsigned-valid")
    static let invalidFile = TestCertificates.certificate(name: "invalidCertFile")
    static let gcxLeafWildcardExpired = TestCertificates.certificate(name: "gcx-wildcard-expired")
    
    // Disig test certificates http://testssl-expire.disig.sk/index.en.html
    static let disigRootCA = TestCertificates.certificate(name: "CA Disig Root R2")
    static let disigIntermediateCA = TestCertificates.certificate(name: "CA Disig R2I2 Certification Service")
    static let disigLeafValid = TestCertificates.certificate(name: "testssl-valid-r2i2.disig.sk")
    static let disigLeafExpired = TestCertificates.certificate(name: "testssl-expire-r2i2.disig.sk")
    static let disigLeafRevoked = TestCertificates.certificate(name: "testssl-revoked-r2i2.disig.sk")
    
    static func certificate(name fileName: String) -> SecCertificate {
        class Bundle {}
        let filePath = Foundation.Bundle(for: Bundle.self).path(forResource: fileName, ofType: "cer")!
        let data = try! Data(contentsOf: URL(fileURLWithPath: filePath))
        return SecCertificateCreateWithData(nil, data as CFData)!
    }
}

// MARK: - Test TrustStores -

struct TestTrustStores {
    
    static let gcxValidTS = TestTrustStores.trustStore(name: "gcx-valid")
    static let gcxInvalidTS = TestTrustStores.trustStore(name: "gcx-expired")

    
    static func trustStore(name fileName: String) -> URL {
        class Bundle {}
        let filePath = Foundation.Bundle(for: Bundle.self).path(forResource: fileName, ofType: "json.signed")!
        return URL(fileURLWithPath: filePath)
    }
}

// MARK: - Test TrustStoreCertificates

struct TestTrustStoreCertificates {
    
    static let gcx = "MIIFIDCCAwgCCQC2lzaH5C//wDANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJERTEMMAoGA1UECAwDTlJXMRAwDgYDVQQHDAdDb2xvZ25lMRUwEwYDVQQKDAxncmFuZGNlbnRyaXgxDDAKBgNVBAMMA2djeDAeFw0xNzAzMDgwODU0MDVaFw0zNzAzMDMwODU0MDVaMFIxCzAJBgNVBAYTAkRFMQwwCgYDVQQIDANOUlcxEDAOBgNVBAcMB0NvbG9nbmUxFTATBgNVBAoMDGdyYW5kY2VudHJpeDEMMAoGA1UEAwwDZ2N4MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwrtJ3kpJj89hrqQWaeDG2t4ykS87I1JAwNfbxmfHf1Hu8v+uxTjeLgMxRTzbZY5+gN43cK+kKGqJ64rER8NkOqA2/RBEH2+9KmxGZ9DdGx/Vooe4aP+e5gWcxPQF5gRPT/5NbHmM94hyVwDtIX9NVFPTxsk/nRiPlVtgn2bMiia9EhiPC08JVmsk7NX0ZyS5GaKx9D57VWqiBfbz4dr9Uh+A2NtTubcZs2c7IlNUMg4+5lQv/YcU7BwB/bQ2vTlR3ham1m9Q3IcrYfszbuKjBKkxT4esBM6KyVs5+xbmCSDhHIDy0IQtrhH366f+nQrIcXvCIGUkczZwcYK72KhXTrts2PFGkRGkTMfCQAz585y2lhtNTPemhWKeNCWiQjkig1s3bdFXE3NAuljm9GJGA6KvTw9RTq340mo2D1aFILzxmLXeaLyHspwjrMZJPFxEN/BMvPUz3zNPql95n5wpszdZ4DEmgqTfAhmiEsQJJ3Z7uPtfUfUSnQVB1QX5pQx1URCe5k+InV6RMIUCL4a0OfNW/y3S55dPMvKMYHEsl0eWBv4Msf5muVkMwYxxlSPavRf+tPtu8Qp197DvSwzgzojQWxfdEkiQZZAUyfip2g9/vEMbNS2P+5iE5qsrAeJhR9m4xb/8QznpbP8UJ7wbmZKNggdu/+Ao0vfCOMl1XM8CAwEAATANBgkqhkiG9w0BAQ0FAAOCAgEACzDzh+hCkdI8oZs7KAzTmhVXFDTRiZ/uvt6hUPZvfZ/L3S/eHF+HKgk9YmWMO9S8up1/oyefHF9suUqNhs+rFAQjzZKrX7whfQemO8yly8ruS+N/+zPV4Vi5K3x6JbaHznapXdImVjgTh7dLcoYlMQWYFrIWbjJkAGKcxJ/EGRmEXRr276x00B8cEuERGpy6gAJFu6jFO7V+0PQRTh+6th8EsJBt0c7jaISQkbLq/mOYqncAXt1NwqgtLdlICn1p8B8UIwXsGvHWO5lKb2Hon9E6Kx61jxhwNOlGedim0Ry4hcgh51jeEj4vfD2/0s/p5Qar4bJ52hJ4zfA3Q5Kbc6XD6Gsb+BR89TIXkxK7Bqrz/twP4XMZa/bpZomn4fJWbvU8VROxJ2dJOcmhwxCAmRt/g9YXqgX7CbGxkfOlelGwAxTaiE9/Xf4in4Yh0u4i81xGsIhh0wPLKiztAPouac57Er7bJ7Z0mRlzJSvdlUzXiXGIz3FkJMe9Ji00QpLr76X14NOJq3o+yYZFu7Qww0ERP72SW/cMSryxbXaJa8r0kKaXNhgjBjlBvhGw3W9CoqkOL6+ETBXdsv5SyesP8XvT4Q8CZ9eI+yzHhr2bJISX0NfzxDBO0aHW4JHpmj7t5TtVkGJIOz7/qOvCoIpxv2ezTIm2IJqu7OZ7YxfpcHM="
    
}


// MARK: - Test Trusts -

enum TestTrusts {
    
    case validGCXTrustChain
    case expiredGCXTrustChain
    case validGCXIntermediateAndRootOnly
    case validGCXWildcardOnly
    case validGCXRootOnly
    
    case validGCXSelfSigned
    case expiredGCXSelfSigned
    
    case validDisigTrustChain
    case expiredDisigTrustChain
    case revokedDisigTrustChain
    
    var trust: SecTrust {
        let trust: SecTrust
        
        switch self {
        
        case .validGCXTrustChain:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.gcxLeafWildcard,
                TestCertificates.gcxIntermediateCA,
                TestCertificates.gcxRootCA])
            
        case .expiredGCXTrustChain:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.gcxLeafWildcardExpired,
                TestCertificates.gcxIntermediateCA,
                TestCertificates.gcxRootCA])
            
        case .validGCXIntermediateAndRootOnly:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.gcxIntermediateCA,
                TestCertificates.gcxRootCA])
            
        case .validGCXWildcardOnly:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.gcxLeafWildcard])
            
        case .validGCXRootOnly:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.gcxRootCA])
            
        case .validGCXSelfSigned:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.gcxSelfSignedValid])
            
        case .expiredGCXSelfSigned:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.gcxSelfSignedExpired])
            
        case .validDisigTrustChain:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.disigLeafValid,
                TestCertificates.disigIntermediateCA,
                TestCertificates.disigRootCA])
            
        case .expiredDisigTrustChain:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.disigLeafExpired,
                TestCertificates.disigIntermediateCA,
                TestCertificates.disigRootCA])
            
        case .revokedDisigTrustChain:
            trust = TestTrusts.trustWithCertificates([
                TestCertificates.disigLeafRevoked,
                TestCertificates.disigIntermediateCA,
                TestCertificates.disigRootCA])
        }
        return trust
    }
    
    static func trustWithCertificates(_ certificates: [SecCertificate]) -> SecTrust {
        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        SecTrustCreateWithCertificates(certificates as CFTypeRef, policy, &trust)
        
        return trust!
    }
}
