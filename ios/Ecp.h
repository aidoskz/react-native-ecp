#if __has_include(<React/RCTBridgeModule.h>)
#import <React/RCTBridgeModule.h>
#else // back compatibility for RN version < 0.40
#import "RCTBridgeModule.h"
#endif

@import UIKit;

@interface Ecp : NSObject <RCTBridgeModule>

@end

// //
// //  ECP.h
// //  EverflowMobile
// //
// //  Created by Айдос on 9/11/19.
// //  Copyright © 2019 Facebook. All rights reserved.
// //

// #ifndef ECP_h
// #define ECP_h

// #endif /* ECP_h */


// #include <openssl/engine.h>
// #include <openssl/err.h>
// #include <openssl/evp.h>
// #include <openssl/pkcs12.h>
// #include <openssl/x509.h>

// #include <libxml/parser.h>
// #include <libxml/tree.h>
// #include "libxml/c14n.h"
// #include "libxml/xpath.h"
// #include "libxml/xpathInternals.h"

// #include "Base64.h"

// #import <React/RCTBridgeModule.h>


// @interface ECP : NSObject <RCTBridgeModule>


// @end

