//
//  GCXTrustPolicyTestObjC.m
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

@import XCTest;

@import GCXTrustPolicy;

@interface GCXTrustPolicyTestObjC : XCTestCase

@end

@implementation GCXTrustPolicyTestObjC

- (void)test_objc_createManageRetrieveValidate_works {
    
    // Trust policy creation tests for each trust validation type
    GCXTrustManager *trustManager = [GCXTrustManager new];
    
    id<GCXTrustPolicy> defaultPolicy = [trustManager createWithType: GCXValidationTypeStandard hostName: @"defaultHost" certificateBundle: NSBundle.mainBundle customValidation: nil];
    
    id<GCXTrustPolicy> pinCertificatePolicy = [trustManager createWithType: GCXValidationTypePinCertificate hostName: @"pinCertHost" certificateBundle: NSBundle.mainBundle customValidation: nil];
    
    id<GCXTrustPolicy> pinPublicKeyPolicy = [trustManager createWithType: GCXValidationTypePinPublicKey hostName: @"pinPubKey" certificateBundle: NSBundle.mainBundle customValidation: nil];
    
    id<GCXTrustPolicy> disabledPolicy = [trustManager createWithType: GCXValidationTypeDisabled hostName: @"disabledHost" certificateBundle: NSBundle.mainBundle customValidation: nil];

    // Note: The typealias `CustomValidationClosure` is not available on ObjC side. Use ^BOOL(SecTrustRef  _Nullable trust) instead.
    id<GCXTrustPolicy> customPolicy = [trustManager createWithType: GCXValidationTypeCustom hostName: @"customHost" certificateBundle: NSBundle.mainBundle customValidation: ^BOOL(SecTrustRef _Nullable trust) {
        /* more sophistic validataion checks should go here... */
        return NO;
    }];
    
    
    // Trust policy management tests
    XCTAssert(trustManager.allPolicies.count == 0);
    XCTAssert(trustManager.allNames.count == 0);

    NSArray *allCreatedPolicies = @[defaultPolicy, pinCertificatePolicy, pinPublicKeyPolicy, disabledPolicy, customPolicy];
    NSArray *allNames = @[@"defaultHost", @"pinCertHost", @"pinPubKey", @"disabledHost", @"customHost"];

    [trustManager addWithPolicies: allCreatedPolicies];
    
    XCTAssert(trustManager.allPolicies.count == allCreatedPolicies.count);
    XCTAssert(trustManager.allNames.count == allNames.count);

    id<GCXTrustPolicy> removedPolicy = [trustManager removePolicyWithName: @"disabledHost"];

    XCTAssertFalse([trustManager.allPolicies containsObject: removedPolicy], "Policy should be removed from manager.");
    XCTAssert(trustManager.allPolicies.count == allCreatedPolicies.count - 1);
    XCTAssert(trustManager.allNames.count == allNames.count - 1);

    [trustManager addWithPolicy: disabledPolicy];

    XCTAssert(trustManager.allPolicies.count == allCreatedPolicies.count);
    XCTAssert(trustManager.allNames.count == allNames.count);

    
    // Trust policy retrieval and validation tests
    SecTrustRef testTrust = nil;
    
    id<GCXTrustPolicy> defaultHostPolicy = [trustManager policyFor: @"defaultHost"];
    BOOL isTrusted = [defaultHostPolicy validateWithTrust: testTrust];
    XCTAssert(defaultPolicy == defaultHostPolicy, "Objects should be equal.");
    XCTAssertFalse(isTrusted, "That should FAIL in every condition as the test trust here is no valid trust object.");

    id<GCXTrustPolicy> pinCertHostPolicy = [trustManager policyFor: @"pinCertHost"];
    XCTAssert(pinCertificatePolicy == pinCertHostPolicy, "Objects should be equal.");
    isTrusted = [pinCertHostPolicy validateWithTrust: testTrust];
    XCTAssertFalse(isTrusted, "That should FAIL in every condition as the test trust here is no valid trust object.");

    id<GCXTrustPolicy> pinPubKeyPolicy = [trustManager policyFor: @"pinPubKey"];
    XCTAssert(pinPubKeyPolicy == pinPubKeyPolicy, "Objects should be equal.");
    isTrusted = [pinPubKeyPolicy validateWithTrust: testTrust];
    XCTAssertFalse(isTrusted, "That should FAIL in every condition as the test trust here is no valid trust object.");

    id<GCXTrustPolicy> disabledHostPolicy = [trustManager policyFor: @"disabledHost"];
    XCTAssert(disabledPolicy == disabledHostPolicy, "Objects should be equal.");
    isTrusted = [disabledHostPolicy validateWithTrust: testTrust];
    XCTAssertTrue(isTrusted, "That should SUCCEED because disabled validation always returns TRUE regardless of all input.");

    id<GCXTrustPolicy> customHostPolicy = [trustManager policyFor: @"customHost"];
    XCTAssert(customPolicy == customHostPolicy, "Objects should be equal.");
    isTrusted = [customHostPolicy validateWithTrust: testTrust];
    XCTAssertFalse(isTrusted, "That should FAIL because we previously defined custom validation closure to return FALSE.");
}

@end
