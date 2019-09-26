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


RCT_EXPORT_METHOD(sampleMethod:(NSString *)stringArgument numberParameter:(nonnull NSNumber *)numberArgument callback:(RCTResponseSenderBlock)callback)
{
    // TODO: Implement some actually useful functionality
	callback(@[[NSString stringWithFormat: @"numberArgument: %@ stringArgument: %@", numberArgument, stringArgument]]);
}



RCT_EXPORT_METHOD(signBas64:(NSString *)certpath withCertpass:(NSString *)certpass withData:(NSString *)dataBase64:(RCTResponseSenderBlock)callback) {
    NSLog(@"generate signature pkcs11!");
    SSL_load_error_strings();
    OPENSSL_config(NULL);
    OpenSSL_add_all_algorithms();
    ENGINE_load_gost();
    ERR_load_crypto_strings();
    ENGINE_load_openssl();
    ENGINE_register_all_pkey_asn1_meths();
//    SSL_library_init();

    ENGINE *me = ENGINE_get_default_RAND();

    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *basePath = ([paths count] > 0) ? [paths objectAtIndex:0] : nil;

    NSString *pkcs12_path = [[NSBundle bundleWithPath:basePath] pathForResource:@"RSA256_eb6205008e346d10d3993a756e79c425dabab881" ofType:@"p12"];
    
    const int CMD_MANDATORY = 0;
    
    unsigned char *buf;
    buf = "QCpYPS1uEM0HAWmJ49HvVKtZWXQ=";
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

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in signer certificate and private key */
    NSString *certPaths = [[NSBundle bundleWithPath:basePath] pathForResource:@"signer" ofType:@"pem"];
    tbio = BIO_new_file([certPaths UTF8String], "r");
    cert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    BIO_reset(tbio);

    key = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);


    /* Open content being signed */
    NSString *signPaths = [[NSBundle bundleWithPath:basePath] pathForResource:@"sign" ofType:@"txt"];
    in = BIO_new_file([signPaths UTF8String], "r");


    /* Sign content */
    cms = CMS_sign(cert, key, NULL, in, flags);

    NSString *smoutPaths = [[NSBundle bundleWithPath:basePath] pathForResource:@"smout" ofType:@"txt"];
    out = BIO_new_file([smoutPaths UTF8String], "w");


    if (!(flags & CMS_STREAM))
        BIO_reset(in);
    SMIME_write_CMS(out, cms, in, flags);


    ret = 0;

    BIO *data = BIO_new(BIO_s_mem()); //If you want input data not from fs
    BIO_puts(data, "Fucking iOS!");
//    BIO_puts(data, inputData);
    //    BIO *data = BIO_new_file([[basePath stringByAppendingString:@"/input"] UTF8String], "rb"); //For example, it reads input data from file with name "./input"
    if(!data) {
        NSLog(@"ERROR AT BIO INPUT FILE!!!");
    }

    //
    EVP_MD_CTX md_ctx;
    const EVP_MD *md = NULL;
    int sig_len;
    //Algorithm
//    int algnid = key->type;
//    if(algnid == NID_id_GostOld34310_2004) {
//        md = EVP_get_digestbynid(NID_id_GostOld34311_95); //64
//        sig_len = 64;
//    } else if(algnid == NID_id_Gost34310_2004) {
//        md = EVP_get_digestbynid(NID_id_Gost34311_95);
//        sig_len = 64;
//    } else {
        //SOON, extra algs and other lengs
        md = EVP_sha1(); //TODO deprecated, use new one for RSA!
        sig_len = 256;
//    }

    char *data2 = inputData;
    unsigned char sig_buf [sig_len];
    // Голая подпись
    EVP_SignInit(&md_ctx, md);
    EVP_SignUpdate (&md_ctx, data2, strlen(data2));
    sig_len = sizeof(sig_buf);

    if (EVP_SignFinal (&md_ctx, sig_buf, &sig_len, key) != 1) {
        ERR_print_errors_fp(stderr);
    }
    NSString *signf = [basePath stringByAppendingString:@"/signpkcs11"];
    NSData* sign = [NSData dataWithBytes:(const void *)sig_buf length:sizeof(sig_buf)];
    [sign writeToFile:signf atomically:NO];

    /* signing */
    CMS_ContentInfo *ci = CMS_sign(cert, key, NULL, data, CMS_BINARY | CMS_NOSMIMECAP); //With source data attach
    ////    CMS_ContentInfo *ci = CMS_sign(key_cert, key, extra_certs, data, CMS_BINARY | CMS_NOSMIMECAP | CMS_DETACHED); // Without attached source data
    if(!ci) {
        NSLog(@"error coult not create signing structure");
    }
    
    NSLog(@"CMS: %s" , ci);


    NSLog(@"done");

errors:

    CMS_ContentInfo_free(ci);

    EVP_PKEY_free(key);


    BIO_free(data);

    ERR_print_errors_fp(stderr);

    ERR_remove_state(/* pid= */ 0);
    ENGINE_cleanup();
    CONF_modules_unload(/* all= */ 1);
    //    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
    NSLog(@"generate signature pkcs11 complete!!!");
}



RCT_EXPORT_METHOD(signData:(NSString *)certpath withCertpass:(NSString *)certpass withData:(NSString *)data:(RCTResponseSenderBlock)callback) {
  
  
  
 OpenSSL_add_all_algorithms();
 ENGINE_load_gost();
 ERR_load_crypto_strings();

//  NSLog(@"PATH: %@ PASS: %@", certpath ,certpass);
//  NSLog(@"Sign Base 64");
 NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);

 NSString *basePath = ([paths count] > 0) ? [paths objectAtIndex:0] : nil;

 NSString *pkcs12_path = [[NSBundle bundleWithPath:basePath] pathForResource:@"RSA256_eb6205008e346d10d3993a756e79c425dabab881" ofType:@"p12"];

//  NSData *xmlData = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"test" ofType:@"xml"]];
//  if(!xmlData) {
//    NSLog(@"Xml was not loaded");
//  }

 unsigned char *cXml = (unsigned char *) [data UTF8String];
//  NSData *xmlData = @"<data>123</data>";
//  unsigned char *cXml = (unsigned char*)malloc(xmlData.length);
//  [xmlData getBytes:cXml length:xmlData.length];
//  cXml[xmlData.length] = 0x0;
//  NSLog(@"original xml = %s", cXml);


 xmlDocPtr doc = NULL;
 xmlNodePtr root = NULL, signEl = NULL, sInfoEl = NULL, canMethEl = NULL, signMethEl = NULL, refEl = NULL, transEl = NULL, tranEl = NULL, tran2El = NULL, digMethEl = NULL, digValEl = NULL, sigValEl = NULL, kInfoEl = NULL, x509DataEl = NULL, x509CertEl = NULL;

 FILE *fp;
 PKCS12 *p12;
 EVP_PKEY *pkey;
 X509 *cert;
 int err;

 STACK_OF(X509) *ca = NULL;
//  NSLog(@"PKCS#12: %@", pkcs12_path);
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

 if (!PKCS12_parse(p12, "aidos123", &pkey, &cert, &ca)) { //Error at parsing or password error
   fprintf(stderr, "Error parsing PKCS#12 file\n");
   ERR_print_errors_fp(stderr);
 }

 int len;
 unsigned char *buf;
 unsigned char *pem;
 buf = NULL;
 len = i2d_X509(cert, &buf);
 pem = base64encode(buf, len);
//  NSLog(@"pem = %s\n\n", pem);

 PKCS12_free(p12);

 doc = xmlParseDoc(cXml);
 xmlChar* c14nXML = NULL;
 xmlC14NDocDumpMemory(doc, NULL, 0, NULL, 0, &c14nXML);
 int c14nXMLLen = strlen((char*)c14nXML);

 EVP_MD_CTX *mdCtx;
 EVP_MD *md;
 xmlChar *xmlHashAlg = ALG_GOST34311;
 xmlChar *xmlSignAlg = ALG_GOST34310;
 //
 int algnid = OBJ_obj2nid(cert->cert_info->signature->algorithm);
 //    if(algnid == NID_id_GostOld34311_95_with_GostOld34310_2004 || algnid == NID_id_Gost34311_95_with_Gost34310_2004) {
 //        md = EVP_get_digestbynid(NID_id_Gost34311_95);
 //        xmlHashAlg = ALG_GOST34311;
 //        xmlSignAlg = ALG_GOST34310;
 //    } else if(algnid == NID_sha256WithRSAEncryption) {
 md = EVP_sha256();
 xmlHashAlg = ALG_SHA256;
 xmlSignAlg = ALG_RSA256;
 //    } else if(algnid == NID_sha1WithRSAEncryption) {
 //        md = EVP_sha1();
 //        xmlHashAlg = ALG_SHA1;
 //        xmlSignAlg = ALG_RSA;
 //    }
 unsigned char *cHash = (unsigned char*)malloc(EVP_MD_size(md));
 unsigned int cHashLen;
 mdCtx = EVP_MD_CTX_create();
 EVP_DigestInit_ex(mdCtx, md, NULL);
 EVP_DigestUpdate(mdCtx, c14nXML, c14nXMLLen);
 EVP_DigestFinal_ex(mdCtx, cHash, &cHashLen);
 EVP_MD_CTX_cleanup(mdCtx);

 char *base64Digest = base64encode(cHash, cHashLen);
//  NSLog(@"Encoded hash: %s", base64Digest);

 xmlXPathContextPtr xpathCtx;
 xmlXPathObjectPtr xpathObj;
 xmlNodeSetPtr sInfoNS;

 // создаем Signature и заполняем
 root = xmlDocGetRootElement(doc);
 signEl = xmlNewNode(NULL, BAD_CAST "ds:Signature");
 xmlNsPtr signNS = xmlNewNs(signEl, NS_XMLDSIG, BAD_CAST "ds");
 xmlAddChild(root, signEl);
 sInfoEl = xmlNewChild(signEl, signNS, BAD_CAST "SignedInfo", NULL);
 canMethEl = xmlNewChild(sInfoEl, signNS, BAD_CAST "CanonicalizationMethod", NULL);
 xmlNewProp(canMethEl, BAD_CAST "Algorithm", C14N_OMIT_COMMENTS);
 signMethEl = xmlNewChild(sInfoEl, signNS, BAD_CAST "SignatureMethod", NULL);
 xmlNewProp(signMethEl, BAD_CAST "Algorithm", xmlSignAlg);
 refEl = xmlNewChild(sInfoEl, signNS, BAD_CAST "Reference", NULL);
 xmlNewProp(refEl, BAD_CAST "URI", NULL);
 transEl = xmlNewChild(refEl, signNS, BAD_CAST "Transforms", NULL);
 tranEl = xmlNewChild(transEl, signNS, BAD_CAST "Transform", NULL);
 xmlNewProp(tranEl, BAD_CAST "Algorithm", ALG_TRANSFORM);
 tran2El = xmlNewChild(transEl, signNS, BAD_CAST "Transform", NULL);
 xmlNewProp(tran2El, BAD_CAST "Algorithm", C14N_WITH_COMMENTS);
 digMethEl = xmlNewChild(refEl, signNS, BAD_CAST "DigestMethod", NULL);
 xmlNewProp(digMethEl, BAD_CAST "Algorithm", xmlHashAlg);
 digValEl = xmlNewChild(refEl, signNS, BAD_CAST "DigestValue", BAD_CAST base64Digest);

 xpathCtx = xmlXPathNewContext(doc);
 xmlXPathRegisterNs(xpathCtx, BAD_CAST "ds", NS_XMLDSIG);
 xpathObj = xmlXPathEvalExpression(BAD_CAST "(//. | //@* | //namespace::*)[ancestor-or-self::ds:SignedInfo]", xpathCtx);
 sInfoNS = xpathObj->nodesetval;

 xmlChar *c14nSInfo = NULL;
 xmlC14NDocDumpMemory(doc, sInfoNS, 0, NULL, 1, &c14nSInfo);
 xmlXPathFreeObject(xpathObj);
 xmlXPathFreeContext(xpathCtx);

 int c14nSInfoLen = strlen((char*)c14nSInfo);
//  NSLog(@"Canonicalized SignedInfo = %s", c14nSInfo);
//  NSLog(@"key size = %d", EVP_PKEY_size(pkey));

 // подписываем
 unsigned char *cSignature = (unsigned char*)malloc(EVP_PKEY_size(pkey));
 unsigned int sigLen;
 EVP_SignInit_ex(mdCtx, md, NULL);
 EVP_SignUpdate (mdCtx, c14nSInfo, c14nSInfoLen);
 EVP_SignFinal (mdCtx, cSignature, &sigLen, pkey);

 // вообще, так надо проверять каждую функцию библиотеки провайдера
 // и что-то предпринимать
 if (err != 1) {
   ERR_print_errors_fp(stderr);
 }

 char *base64Signature = base64encode(cSignature, sigLen);
//  NSLog(@"Encoded signature: %s", base64Signature);


 //    // BASE64 SIGN
 //
 //    EVP_MD_CTX md_ctx;// = EVP_MD_CTX_create();
 //    //    const EVP_MD *md = EVP_get_digestbynid(NID_id_GostOld34311_95); //64
 //    const EVP_MD *md = EVP_get_digestbynid(1);
 //
 //
 //    char *data = "5x3XKy40nmCjBK9+PRNiGHbHt7E=";
 //
 //    //Singing
 //    EVP_SignInit(&md_ctx, md);
 //    EVP_SignUpdate (&md_ctx, data, strlen(data));
 //    sig_len = sizeof(cSignature);
 //    err = EVP_SignFinal (&md_ctx, cSignature, &sig_len, pkey);
 //
 //    if (err != 1) {
 //        ERR_print_errors_fp(stderr);
 //        exit (1);
 //    }
 //    EVP_PKEY_free(pkey);
 //    NSData* sign = [NSData dataWithBytes:(const void *)sig_buf length:sizeof(sig_buf)];
 //    [sign writeToFile:signf atomically:NO];
 //
 //    pkey = X509_get_pubkey(cert);
 //    // BASE64 END




 //
 // дописываем xml
 sigValEl = xmlNewChild(signEl, signNS, BAD_CAST "SignatureValue", BAD_CAST base64Signature);
 kInfoEl = xmlNewChild(signEl, signNS, BAD_CAST "KeyInfo", NULL);
 x509DataEl = xmlNewChild(kInfoEl, signNS, BAD_CAST "X509Data", NULL);
//  NSLog(@"CERTIFICATE %s" , pem);
 x509CertEl = xmlNewChild(x509DataEl, signNS, BAD_CAST "X509Certificate", BAD_CAST pem);
//
//  NSLog(@"XML CERT %s", signEl);

 // выдаем подписанный xml
 xmlChar *outXML;
 int outXMLSize;
 xmlDocDumpMemoryEnc(doc, &outXML, &outXMLSize, "UTF-8");
//  NSLog(@"signed xml = %s", outXML);
 // сохраняем в файл
 NSData *signedXML = [NSData dataWithBytes:outXML length:outXMLSize];
 NSString *signedXMLPath = [basePath stringByAppendingString:@"/signedXML.xml"];
//  NSLog(signedXMLPath);
 [signedXML writeToFile:signedXMLPath atomically:NO];

 xmlFreeDoc(doc);
 xmlCleanupParser();
 xmlMemoryDump();
 EVP_PKEY_free(pkey);
 X509_free(cert);
 EVP_MD_CTX_destroy(mdCtx);
 ERR_free_strings();
 //        EVP_cleanup(); вызываем только, когда абсолютно все завершили
//  callback(@[[NSNull null], [NSNumber numberWithInt:(1*2)]]);
 callback(@[[NSNull null], [NSString stringWithUTF8String:pem], paths ]);
    callback(@[[NSNull null], certpath, certpass ]);
}


@end
