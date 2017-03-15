//
//  TrustDirectivePinCertificateOnlineTests.swift
//  GCXTrustPolicy
//
//  Created by Stefan Horst on 07.03.17.
//  Copyright © 2016 grandcentrix GmbH. All rights reserved.
//

import XCTest

@testable
import GCXTrustPolicy

class TrustDirectivePinCertificateOnlineTests: XCTestCase {
    
    
    // MARK: - Variables -
    
    var isValid:Bool!
    var directive: PinCertificateOnlineDirective!
    var testHost: String!
    var trust: SecTrust!
    var testCustomer: String!
    let trustServer = TestTrustStores.gcxValidTS
    let trustServerCertificate = TestTrustStoreCertificates.gcx


    // MARK: - Certificate Pinning -
    
    func test_validation_selfSignedVersusSelfSigned_correctBehaviour() {
        
        // local self-signed certificate
        // vs. remote self-signed certificate
        trust = TestTrusts.validGCXTrustChain.trust
        testHost = "grandcentrix.net"
        testCustomer = "gcx"
        
        directive = PinCertificateOnlineDirective(trustServer: trustServer, trustServerCertificate: Data(base64Encoded: trustServerCertificate)!, customer: testCustomer, hostName: testHost, validateServerTrust: true, validateHost: true)
        isValid = directive.validate(with: trust)
        
        XCTAssertTrue(isValid, "Validation should succeed.")
    }
}
