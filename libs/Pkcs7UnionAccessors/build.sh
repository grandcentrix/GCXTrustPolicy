#!/bin/bash

# This script builds the iOS and Mac openSSL libraries with Bitcode enabled
# Download openssl http://www.openssl.org/source/ and place the tarball next to this script

# Credits:
# https://github.com/st3fan/ios-openssl
# https://github.com/x2on/OpenSSL-for-iPhone/blob/master/build-libssl.sh
# Peter Steinberger, PSPDFKit GmbH, @steipete.
# Doron Adler, GlideTalk, @Norod78

# Updated to work with Xcode 7 and iOS 9

set -e

###################################
# 		 SDK Version
###################################
IOS_SDK_VERSION=$(xcodebuild -version -sdk iphoneos | grep SDKVersion | cut -f2 -d ':' | tr -d '[[:space:]]')
###################################

################################################
# 		 Minimum iOS deployment target version
################################################
MIN_IOS_VERSION="7.0"

################################################
# 		 Minimum OS X deployment target version
################################################
MIN_OSX_VERSION="10.7"

echo "----------------------------------------"
echo "iOS SDK version: ${IOS_SDK_VERSION}"
echo "iOS deployment target: ${MIN_IOS_VERSION}"
echo "OS X deployment target: ${MIN_OSX_VERSION}"
echo "----------------------------------------"
echo " "

DEVELOPER=`xcode-select -print-path`
buildMac()
{
	ARCH=$1
	echo "Start Building for ${ARCH}"
	export CC="${BUILD_TOOLS}/usr/bin/clang -arch ${ARCH} -mmacosx-version-min=${MIN_OSX_VERSION}"

	FILENAME=mac_${ARCH}_pkcs7_union_accessors

	$CC -c pkcs7_union_accessors.c -o ${FILENAME}.o -I../OpenSSL/include
	ar rcs ${FILENAME}.a ${FILENAME}.o
	rm ${FILENAME}.o
}
buildIOS()
{
	ARCH=$1
	echo "Start Building for ${PLATFORM} ${IOS_SDK_VERSION} ${ARCH}"
	
	if [[ "${ARCH}" == "i386" || "${ARCH}" == "x86_64" ]]; then
		PLATFORM="iPhoneSimulator"
	else
		PLATFORM="iPhoneOS"
	fi

	export $PLATFORM
	export CROSS_TOP="${DEVELOPER}/Platforms/${PLATFORM}.platform/Developer"
	export CROSS_SDK="${PLATFORM}${IOS_SDK_VERSION}.sdk"
	export BUILD_TOOLS="${DEVELOPER}"
	export CC="${BUILD_TOOLS}/usr/bin/gcc -fembed-bitcode -mios-version-min=${MIN_IOS_VERSION} -arch ${ARCH} -isysroot ${CROSS_TOP}/SDKs/${CROSS_SDK}"

	FILENAME=iOS_${ARCH}_pkcs7_union_accessors

	$CC -c pkcs7_union_accessors.c -o ${FILENAME}.o -I../OpenSSL/include
	ar rcs ${FILENAME}.a ${FILENAME}.o
	rm ${FILENAME}.o

	echo "Done Building for ${ARCH}"
}
mkdir -p lib/iOS
mkdir -p lib/Mac

buildMac "i386"
buildMac "x86_64"

echo "Building Mac libraries"
lipo \
	"mac_i386_pkcs7_union_accessors.a" \
	"mac_x86_64_pkcs7_union_accessors.a" \
	-create -output lib/Mac/libpkcs7_union_accessors.a

rm mac_*_pkcs7_union_accessors.a

buildIOS "armv7"
buildIOS "arm64"
buildIOS "x86_64"
buildIOS "i386"
echo "Building iOS libraries"
lipo \
	"iOS_armv7_pkcs7_union_accessors.a" \
	"iOS_arm64_pkcs7_union_accessors.a" \
	"iOS_i386_pkcs7_union_accessors.a" \
	"iOS_x86_64_pkcs7_union_accessors.a" \
	-create -output lib/iOS/libpkcs7_union_accessors.a

rm iOS_*_pkcs7_union_accessors.a

echo "Done"
