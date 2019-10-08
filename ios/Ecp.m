#import "Ecp.h"

const xmlChar* NS_XMLDSIG = BAD_CAST "http://www.w3.org/2000/09/xmldsig#";
const xmlChar* C14N_OMIT_COMMENTS = BAD_CAST "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const xmlChar* C14N_WITH_COMMENTS = BAD_CAST "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
const xmlChar* ALG_GOST34310 = BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311";
const xmlChar* ALG_TRANSFORM = BAD_CAST "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const xmlChar* ALG_GOST34311 = BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#gost34311";
const xmlChar* ALG_RSA256 = BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const xmlChar* ALG_SHA256 = BAD_CAST "http://www.w3.org/2001/04/xmlenc#sha256";
const xmlChar* ALG_RSA = BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1";
const xmlChar* ALG_SHA1 = BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#sha1";


#if __has_include(<React/RCTConvert.h>)
#import <React/RCTConvert.h>
#import <React/RCTBridge.h>
#else // back compatibility for RN version < 0.40
#import "RCTConvert.h"
#import "RCTBridge.h"
#endif

@implementation Ecp

+ (BOOL)requiresMainQueueSetup {
    return NO;
}

- (dispatch_queue_t)methodQueue
{
    return dispatch_get_main_queue();
}

RCT_EXPORT_MODULE()


//
//RCT_EXPORT_METHOD(signBas64:(NSString *)certpath withCertpass:(NSString *)certpass withData:(NSString *)dataBase64:(RCTResponseSenderBlock)callback) {
//    NSLog(@"generate signature pkcs11!");
//    SSL_load_error_strings();
//    OPENSSL_config(NULL);
//    OpenSSL_add_all_algorithms();
//    ENGINE_load_gost();
//    ERR_load_crypto_strings();
//    ENGINE_load_openssl();
//    ENGINE_register_all_pkey_asn1_meths();
////    SSL_library_init();
//
//    ENGINE *me = ENGINE_get_default_RAND();
//
//    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
//    NSString *basePath = ([paths count] > 0) ? [paths objectAtIndex:0] : nil;
//
//    NSString *pkcs12_path = [[NSBundle bundleWithPath:basePath] pathForResource:@"RSA256_eb6205008e346d10d3993a756e79c425dabab881" ofType:@"p12"];
//
//    const int CMD_MANDATORY = 0;
//
//    unsigned char *buf;
//    buf = "QCpYPS1uEM0HAWmJ49HvVKtZWXQ=";
//    int indata_len = strlen(buf);
//
//    const char *inputData = base64decode(buf, indata_len);
//
//
//    BIO *in = NULL, *out = NULL, *tbio = NULL;
//    X509 *cert = NULL;
//    EVP_PKEY *key = NULL;
//    CMS_ContentInfo *cms = NULL;
//    int ret = 1;
//
//    /*
//     * For simple S/MIME signing use CMS_DETACHED. On OpenSSL 1.0.0 only: for
//     * streaming detached set CMS_DETACHED|CMS_STREAM for streaming
//     * non-detached set CMS_STREAM
//     */
//    int flags = CMS_DETACHED | CMS_STREAM;
//
//    OpenSSL_add_all_algorithms();
//    ERR_load_crypto_strings();
//
//    /* Read in signer certificate and private key */
//    NSString *certPaths = [[NSBundle bundleWithPath:basePath] pathForResource:@"signer" ofType:@"pem"];
//    tbio = BIO_new_file([certPaths UTF8String], "r");
//    cert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
//
//    BIO_reset(tbio);
//
//    key = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);
//
//
//    /* Open content being signed */
//    NSString *signPaths = [[NSBundle bundleWithPath:basePath] pathForResource:@"sign" ofType:@"txt"];
//    in = BIO_new_file([signPaths UTF8String], "r");
//
//
//    /* Sign content */
//    cms = CMS_sign(cert, key, NULL, in, flags);
//
//    NSString *smoutPaths = [[NSBundle bundleWithPath:basePath] pathForResource:@"smout" ofType:@"txt"];
//    out = BIO_new_file([smoutPaths UTF8String], "w");
//
//
//    if (!(flags & CMS_STREAM))
//        BIO_reset(in);
//    SMIME_write_CMS(out, cms, in, flags);
//
//
//    ret = 0;
//
//    BIO *data = BIO_new(BIO_s_mem()); //If you want input data not from fs
//    BIO_puts(data, "Fucking iOS!");
////    BIO_puts(data, inputData);
//    //    BIO *data = BIO_new_file([[basePath stringByAppendingString:@"/input"] UTF8String], "rb"); //For example, it reads input data from file with name "./input"
//    if(!data) {
//        NSLog(@"ERROR AT BIO INPUT FILE!!!");
//    }
//
//    //
//    EVP_MD_CTX md_ctx;
//    const EVP_MD *md = NULL;
//    int sig_len;
//    //Algorithm
////    int algnid = key->type;
////    if(algnid == NID_id_GostOld34310_2004) {
////        md = EVP_get_digestbynid(NID_id_GostOld34311_95); //64
////        sig_len = 64;
////    } else if(algnid == NID_id_Gost34310_2004) {
////        md = EVP_get_digestbynid(NID_id_Gost34311_95);
////        sig_len = 64;
////    } else {
//        //SOON, extra algs and other lengs
//        md = EVP_sha1(); //TODO deprecated, use new one for RSA!
//        sig_len = 256;
////    }
//
//    char *data2 = inputData;
//    unsigned char sig_buf [sig_len];
//    // Голая подпись
//    EVP_SignInit(&md_ctx, md);
//    EVP_SignUpdate (&md_ctx, data2, strlen(data2));
//    sig_len = sizeof(sig_buf);
//
//    if (EVP_SignFinal (&md_ctx, sig_buf, &sig_len, key) != 1) {
//        ERR_print_errors_fp(stderr);
//    }
//    NSString *signf = [basePath stringByAppendingString:@"/signpkcs11"];
//    NSData* sign = [NSData dataWithBytes:(const void *)sig_buf length:sizeof(sig_buf)];
//    [sign writeToFile:signf atomically:NO];
//
//    /* signing */
//    CMS_ContentInfo *ci = CMS_sign(cert, key, NULL, data, CMS_BINARY | CMS_NOSMIMECAP); //With source data attach
//    ////    CMS_ContentInfo *ci = CMS_sign(key_cert, key, extra_certs, data, CMS_BINARY | CMS_NOSMIMECAP | CMS_DETACHED); // Without attached source data
//    if(!ci) {
//        NSLog(@"error coult not create signing structure");
//    }
//
//    NSLog(@"CMS: %s" , ci);
//
//
//    NSLog(@"done");
//
//errors:
//
//    CMS_ContentInfo_free(ci);
//
//    EVP_PKEY_free(key);
//
//
//    BIO_free(data);
//
//    ERR_print_errors_fp(stderr);
//
//    ERR_remove_state(/* pid= */ 0);
//    ENGINE_cleanup();
//    CONF_modules_unload(/* all= */ 1);
//    //    EVP_cleanup();
//    ERR_free_strings();
//    CRYPTO_cleanup_all_ex_data();
//    NSLog(@"generate signature pkcs11 complete!!!");
//}

-(NSArray *)listFileAtPath:(NSString *)path
{
    //-----> LIST ALL FILES <-----//
    NSLog(@"LISTING ALL FILES FOUND");
    
    int count;
    
    NSArray *directoryContent = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:path error:NULL];
    for (count = 0; count < (int)[directoryContent count]; count++)
    {
        NSLog(@"File %d: %@", (count + 1), [directoryContent objectAtIndex:count]);
    }
    return directoryContent;
}


RCT_EXPORT_METHOD(listDocument: (RCTResponseSenderBlock)callback)
{
    
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *basePath = ([paths count] > 0) ? [paths objectAtIndex:0] : nil;
    int count;
    
    NSArray *directoryContent = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:basePath error:NULL];
    for (count = 0; count < (int)[directoryContent count]; count++)
    {
        NSLog(@"File %d: %@", (count + 1), [directoryContent objectAtIndex:count]);
    }
    callback(@[directoryContent]);
}


RCT_EXPORT_METHOD(sampleMethod: (NSString *)certpath withCertpass: (NSString *)certpass withData: (NSString *) data: (RCTResponseSenderBlock)errorcallback: (RCTResponseSenderBlock)callback) {
    
    OpenSSL_add_all_algorithms();
    ENGINE_load_gost();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    OPENSSL_config(NULL);
    ENGINE_load_openssl();
    ENGINE_register_all_pkey_asn1_meths();
    SSL_library_init();
//  NSLog(@"PATH: %@ PASS: %@", certpath ,certpass);
//  NSLog(@"Sign Base 64");
NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);

NSString *basePath = ([paths count] > 0) ? [paths objectAtIndex:0] : nil;

NSString *pkcs12_path = [[NSBundle bundleWithPath:basePath] pathForResource:certpath ofType:@"p12"];

NSLog(@"generate signature pkcs11!");

ENGINE *me = ENGINE_get_default_RAND();

 
const int CMD_MANDATORY = 0;

unsigned char *buf;
buf = [data UTF8String];
int indata_len = strlen(buf);

const char *inputData = base64decode(buf, indata_len);


BIO *in = NULL, *out = NULL, *tbio = NULL;
X509 *cert = NULL;
EVP_PKEY *key = NULL;
CMS_ContentInfo *cms = NULL;
int ret = 1;

/*
 * For simple S/MIME signing use CMS_DETACHED. On OpenSSL 1.0.0 only: for
 * streaming detached set CMS_DETACHED|CMS_STREAM for streaming
 * non-detached set CMS_STREAM
 */
int flags = CMS_DETACHED | CMS_STREAM;


/* Read in signer certificate and private key */
NSString *certPaths = [[NSBundle bundleWithPath:basePath] pathForResource:certpath ofType:@"p12"];

FILE *fp;
PKCS12 *p12;
EVP_PKEY *pkey;
int err;

STACK_OF(X509) *ca = NULL;
NSLog(@"PKCS#12: %@", pkcs12_path);
if([[NSFileManager defaultManager] fileExistsAtPath:pkcs12_path]) {
    NSLog(@"ok, pfile exists!");
} else {
    NSLog(@"error, pfile does not exists!");
}

fp = fopen([pkcs12_path UTF8String], "rb");
p12 = d2i_PKCS12_fp(fp, NULL);
fclose (fp);
if (!p12) {
    fprintf(stderr, "Error reading PKCS#12 file\n");
    ERR_print_errors_fp(stderr);
}

if (!PKCS12_parse(p12, "12345678", &pkey, &cert, &ca)) { //Error at parsing or password error
    fprintf(stderr, "Error parsing PKCS#12 file\n");
    ERR_print_errors_fp(stderr);
}


//    tbio = BIO_new_file([certPaths UTF8String], "r");
//    cert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

//    BIO_reset(tbio);

//    key = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);

/* Open content being signed */


BIO *dataforsign = BIO_new(BIO_s_mem()); //If you want input data not from fs
BIO_puts(dataforsign, inputData);
//    BIO_puts(data, inputData);

/* Sign content */
cms = CMS_sign(cert, pkey, NULL, dataforsign, flags);

NSString *smoutPaths = [[NSBundle bundleWithPath:basePath] pathForResource:@"smout" ofType:@"txt"];
out = BIO_new_file([smoutPaths UTF8String], "w");

int  cmsLen = sizeof(cms);
if (!(flags & CMS_STREAM))
    BIO_reset(in);
SMIME_write_CMS(out, cms, dataforsign, flags);
    NSLog(@"CMS BASE64 %s", base64encode(cms, cmsLen ));
ret = 0;
    
if(!data) {
    NSLog(@"ERROR AT BIO INPUT FILE!!!");
}

//
EVP_MD_CTX md_ctx;
const EVP_MD *md = NULL;
int sig_len;
//Algorithm
int algnid = pkey->type;
if(algnid == NID_id_GostOld34310_2004) {
    md = EVP_get_digestbynid(NID_id_GostOld34311_95); //64
    sig_len = 64;
} else if(algnid == NID_id_Gost34310_2004) {
    md = EVP_get_digestbynid(NID_id_Gost34311_95);
    sig_len = 64;
} else {
    //SOON, extra algs and other lengs
    md = EVP_sha1(); //TODO deprecated, use new one for RSA!
    sig_len = 256;
}

char *data2 = inputData;

int dataLen =  strlen(data2);

char *dataEncoded = base64encode(data2, strlen(data2));

NSLog(@"dataEncoded : %s" , dataEncoded);
unsigned char sig_buf [sig_len];
// Голая подпись
EVP_SignInit(&md_ctx, md);
EVP_SignUpdate (&md_ctx, dataEncoded, dataLen);
sig_len = sizeof(sig_buf);

if (EVP_SignFinal (&md_ctx, sig_buf, &sig_len, key) != 1) {
    ERR_print_errors_fp(stderr);
}

NSData* sign = [NSData dataWithBytes:(const void *)sig_buf length:sizeof(sig_buf)];
//[sign writeToFile:smoutPaths atomically:NO];

NSLog(@" sign : %s" , sign);

/* signing */
CMS_ContentInfo *ci = CMS_sign(cert, pkey, NULL, dataforsign, CMS_BINARY | CMS_NOSMIMECAP); //With source data attach
////    CMS_ContentInfo *ci = CMS_sign(key_cert, key, extra_certs, data, CMS_BINARY | CMS_NOSMIMECAP | CMS_DETACHED); // Without attached source data
SMIME_write_CMS(out, ci, dataforsign, flags);
//[self.txtCMS setText:[NSString stringWithUTF8String: sig_buf]];
if(!ci) {
    NSLog(@"error coult not create signing structure");
}

NSLog(@"CMS: %s" , ci);
    
    NSString *content = [NSString stringWithContentsOfFile:smoutPaths
                                                  encoding:NSUTF8StringEncoding
                                                     error:NULL];
    // maybe for debugging...
    NSLog(@"contents: %@", content);
    


NSLog(@"done");

errors:

CMS_ContentInfo_free(ci);

EVP_PKEY_free(pkey);


BIO_free(dataforsign);
ERR_print_errors_fp(stderr);

ERR_remove_state(/* pid= */ 0);
//    ENGINE_cleanup();
CONF_modules_unload(/* all= */ 1);
//    EVP_cleanup();
ERR_free_strings();
CRYPTO_cleanup_all_ex_data();
NSLog(@"generate signature pkcs11 complete!!!");
    
    
EVP_PKEY_free(pkey);
X509_free(cert);
//EVP_MD_CTX_destroy(mdCt   x);
ERR_free_strings();
//        EVP_cleanup(); вызываем только, когда абсолютно все завершили
//  callback(@[[NSNull null], [NSNumber numberWithInt:(1*2)]]);
//callback(@[[NSNull null], [NSString stringWithUTF8String:pem], paths ]);
callback(@[[NSNull null], certpath, certpass ]);
}


@end
