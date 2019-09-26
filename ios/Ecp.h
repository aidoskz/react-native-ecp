#if __has_include(<React/RCTBridgeModule.h>)
#import <React/RCTBridgeModule.h>
#else // back compatibility for RN version < 0.40
#import "RCTBridgeModule.h"
#endif

@import UIKit;



#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include "libxml/c14n.h"
#include "libxml/xpath.h"
#include "libxml/xpathInternals.h"


#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#include <openssl/cms.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/comp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "Base64.h"


@interface Ecp : NSObject <RCTBridgeModule>

@end
