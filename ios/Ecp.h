#if __has_include(<React/RCTBridgeModule.h>)
#import <React/RCTBridgeModule.h>
#else // back compatibility for RN version < 0.40
#import "RCTBridgeModule.h"
#endif

#import <UIKit/UIKit.h>

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>


#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/ocsp.h>
#include <openssl/cms.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/comp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/ts.h>



#define openssl_fdset(a,b) FD_SET((unsigned int)a, b)


#define MAX_VALIDITY_PERIOD (5 * 60)

#include "Base64.h"


@interface Ecp : NSObject <RCTBridgeModule>

@end
