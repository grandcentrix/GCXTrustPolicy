//
//  TrustDirectivePinPublicKeyTests.swift
//  GCXSSLPinning
//
//  Created by Stefan Horst on 07.03.17.
//  Copyright © 2016 grandcentrix GmbH. All rights reserved.
//

import XCTest

@testable
import GCXTrustPolicy

class TrustDirectivePinPublicKeyOnlineTests: XCTestCase {
    
    
    // MARK: - Variables -
    
    var isValid: Bool!
    var directive: PinPublicKeyOnlineDirective!
    var trust: SecTrust!
    var testHost: String!
    let testCustomer = "gcx"
    var trustServer: URL!
    let trustServerCertificate = TestTrustStoreCertificates.gcx
    
    // MARK: - Valid trust chain tests -
    
    func test_validCertificatePinnedKeyOnline_validTrustChain_gotApproved () {
        // www.grandcentrix.net leaf certifcate incl. complete chain
        trust = TestTrusts.validGCXTrustChain.trust
        testHost = "grandcentrix.net"
        trustServer = TestTrustStores.gcxValidTS

        
        directive = PinPublicKeyOnlineDirective(trustServer: trustServer, trustServerCertificate: Data(base64Encoded: trustServerCertificate)!, customer: testCustomer, hostName: testHost, validateServerTrust: true, validateHost: true)
        // remove truststore and force reload
        directive.removeTrustStore()
        
        isValid = directive.validate(with: trust)
        
        XCTAssertTrue(isValid, "Validation should succeed.")
    }
    
    func test_validCertificatePinnedKeyOnline_invalidTrustChain_gotRejected () {
        // www.grandcentrix.net leaf certifcate incl. complete chain
        trust = TestTrusts.expiredGCXTrustChain.trust
        testHost = "grandcentrix.net"
        trustServer = TestTrustStores.gcxValidTS
        
        
        directive = PinPublicKeyOnlineDirective(trustServer: trustServer, trustServerCertificate: Data(base64Encoded: trustServerCertificate)!, customer: testCustomer, hostName: testHost, validateServerTrust: true, validateHost: true)
        // remove truststore and force reload
        directive.removeTrustStore()
        
        isValid = directive.validate(with: trust)
        
        XCTAssertTrue(!isValid, "Validation should not succeed. Certificate is wrong.")
    }
    
    func test_validCertificatePinnedKeyOnline_invalidHost_gotRejected () {
        // www.grandcentrix.net leaf certifcate incl. complete chain
        trust = TestTrusts.validGCXTrustChain.trust
        testHost = "google.com"
        trustServer = TestTrustStores.gcxValidTS
        
        
        directive = PinPublicKeyOnlineDirective(trustServer: trustServer, trustServerCertificate: Data(base64Encoded: trustServerCertificate)!, customer: testCustomer, hostName: testHost, validateServerTrust: true, validateHost: true)
        // remove truststore and force reload
        directive.removeTrustStore()
        
        isValid = directive.validate(with: trust)
        
        XCTAssertTrue(!isValid, "Validation should not succeed. host is wrong.")
    }
    
    func test_validCertificatePinnedKeyOnline_invalidCustomer_gotRejected () {
        // www.grandcentrix.net leaf certifcate incl. complete chain
        trust = TestTrusts.validGCXTrustChain.trust
        testHost = "grandcentrix.net"
        trustServer = TestTrustStores.gcxValidTS
        
        
        directive = PinPublicKeyOnlineDirective(trustServer: trustServer, trustServerCertificate: Data(base64Encoded: trustServerCertificate)!, customer: "invalid", hostName: testHost, validateServerTrust: true, validateHost: true)
        // remove truststore and force reload
        directive.removeTrustStore()
        
        isValid = directive.validate(with: trust)
        
        XCTAssertTrue(!isValid, "Validation should not succeed. invalid customer.")
    }



    func test_validCertificatePinnedKeyOnline_invalid_timestamp_gotRejected () {
        // www.grandcentrix.net leaf certifcate incl. complete chain
        trust = TestTrusts.validGCXTrustChain.trust
        testHost = "grandcentrix.net"
        trustServer = TestTrustStores.gcxInvalidTS
        
        directive = PinPublicKeyOnlineDirective(trustServer: trustServer, trustServerCertificate: Data(base64Encoded: trustServerCertificate)!, customer: testCustomer, hostName: testHost, validateServerTrust: true, validateHost: true)
        // remove truststore and force reload
        directive.removeTrustStore()
       
        
        isValid = directive.validate(with: trust)
        
        XCTAssertTrue(!isValid, "Validation should not succeed. Timestamp is to Old")
    }
    
}
