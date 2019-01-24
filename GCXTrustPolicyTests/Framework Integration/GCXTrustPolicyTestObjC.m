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

- (void)test_integration_objc_shouldWorkFlawlessWithFramework {
    GCXValidationType standardValidationType = GCXValidationTypeStandard;
    GCXComposePolicy *composerA = [[GCXComposePolicy alloc] initWithValidation: standardValidationType forHost: @"A"];
    GCXComposePolicy *composerB = [[GCXComposePolicy alloc] initWithValidation: GCXValidationTypeDisabled forHost: @"B"];
    
    // Note: The typealias `CustomValidationClosure` is not available on ObjC side. Use ^BOOL(SecTrustRef  _Nullable trust) instead.
    GCXComposePolicy *composerC = [[GCXComposePolicy alloc] initWithValidation: GCXValidationTypeCustom forHost: @"C"];
    composerC.customValidation = ^BOOL(SecTrustRef _Nullable trust) {
        // perform a completely custom validation based on the given trust
        return YES;
    };
    
    id<GCXTrustPolicy> defaultPolicy = [composerA create];
    id<GCXTrustPolicy> disabledPolicy = [composerB create];
    id<GCXTrustPolicy> customPolicy = [composerC create];

    NSArray *policies = @[defaultPolicy, disabledPolicy, customPolicy];
    
    GCXTrustManager *manager = [[GCXTrustManager alloc] initWith: policies];
    SecTrustRef trust = nil;
    BOOL isTrusted;
    
    isTrusted = [[manager policyFor: @"A"] validateWith: trust];
    XCTAssertFalse(isTrusted, @"That should fail in every condition as there is no trust object.");
    
    isTrusted = [[manager policyFor: @"B"] validateWith: trust];
    XCTAssertTrue(isTrusted, @"Disabled validation always returns TRUE regardless of all input.");

    isTrusted = [[manager policyFor: @"C"] validateWith: trust];
    XCTAssertTrue(isTrusted, @"We previously defined cusom validation to return TRUE, so it should succeed.");
}



@end
