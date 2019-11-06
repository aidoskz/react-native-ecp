#import "Ecp.h"

#if __has_include(<React/RCTConvert.h>)
#import <React/RCTConvert.h>
#import <React/RCTBridge.h>
#else // back compatibility for RN version < 0.40
#import "RCTConvert.h"
#import "RCTBridge.h"
#endif

@implementation Ecp

- (instancetype)init {
    OpenSSL_add_all_algorithms();
    ENGINE_load_gost();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    OPENSSL_config(NULL);
    ENGINE_load_openssl();
    ENGINE_register_all_pkey_asn1_meths();
    SSL_library_init();
    return self;
}

+ (BOOL)requiresMainQueueSetup {
    return NO;
}

- (dispatch_queue_t)methodQueue
{
    return dispatch_get_main_queue();
}

RCT_EXPORT_MODULE()

static time_t ASN1_GetTimeT(ASN1_TIME* time)
{
    struct tm t;
    const char* str = (const char*) time->data;
    size_t i = 0;
    
    memset(&t, 0, sizeof(t));
    
    if (time->type == V_ASN1_UTCTIME) /* two digit year */
    {
        t.tm_year = (str[i++] - '0') * 10 + (str[++i] - '0');
        if (t.tm_year < 70)
            t.tm_year += 100;
    }
    else if (time->type == V_ASN1_GENERALIZEDTIME) /* four digit year */
    {
        t.tm_year = (str[i++] - '0') * 1000 + (str[++i] - '0') * 100 + (str[++i] - '0') * 10 + (str[++i] - '0');
        t.tm_year -= 1900;
    }
    t.tm_mon = ((str[i++] - '0') * 10 + (str[++i] - '0')) - 1; // -1 since January is 0 not 1.
    t.tm_mday = (str[i++] - '0') * 10 + (str[++i] - '0');
    t.tm_hour = (str[i++] - '0') * 10 + (str[++i] - '0');
    t.tm_min  = (str[i++] - '0') * 10 + (str[++i] - '0');
    t.tm_sec  = (str[i++] - '0') * 10 + (str[++i] - '0');
    
    /* Note: we did not adjust the time based on time zone information */
    return mktime(&t);
}

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
    
    BIO *dataforsign = BIO_new(BIO_s_mem()); //If you want input data not from fs
    BIO_puts(dataforsign, inputData);
    //    BIO_puts(data, inputData);

    NSError  *error = nil;
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

    if (!PKCS12_parse(p12, [certpass UTF8String], &pkey, &cert, &ca)) { //Error at parsing or password error
        fprintf(stderr, "Error parsing PKCS#12 file\n");
        ERR_print_errors_fp(stderr);
        const char *errormessage = "Неверный пароль!";
        BIO_free(dataforsign);
        ERR_print_errors_fp(stderr);
        //
        ERR_remove_state(/* pid= */ 0);
//        ENGINE_cleanup();
        CONF_modules_unload(/* all= */ 1);
        // //    EVP_cleanup();
        //    ERR_free_strings();
        CRYPTO_cleanup_all_ex_data();
        NSLog(@"generate signature pkcs11 complete!!!");
        
        EVP_PKEY_free(pkey);
        X509_free(cert);
        ERR_free_strings();
        errorcallback(@[[NSString stringWithUTF8String:errormessage]]);
        return;
        
    }

    //    tbio = BIO_new_file([certPaths UTF8String], "r");
    //    cert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    //    BIO_reset(tbio);

    //    key = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);

    /* Open content being signed */


    

    /* Sign content */
    cms = CMS_sign(cert, pkey, NULL, dataforsign, flags);
    
    NSError *errorWithFile;
    NSString *stringToWrite = @"1\n2\n3\n4";
    NSString *filePath = [[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject] stringByAppendingPathComponent:@"smout.txt"];
    [stringToWrite writeToFile:filePath atomically:YES encoding:NSUTF8StringEncoding error:&errorWithFile];

    NSString *smoutPaths = [[NSBundle bundleWithPath:basePath] pathForResource:@"smout" ofType:@"txt"];
    
   
//    NSError *errorWithfile;
//    NSString *stringToWrite = @"w";
//    [stringToWrite writeToFile:smoutPaths atomically:YES encoding:NSUTF8StringEncoding error:&errorWithfile];
//
    if(errorWithFile){
        NSLog(@"ERRORWITHFILE ");
        NSLog(errorWithFile);
    }
    NSLog(@"SMOUT %s", [filePath UTF8String]);
    out = BIO_new_file([filePath UTF8String], "w");

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
    EVP_MD *md = NULL;
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

    if (EVP_SignFinal (&md_ctx, data2, &dataLen, key) != 1) {
        ERR_print_errors_fp(stderr);
    }

    NSData* sign = [NSData dataWithBytes:(const void *)sig_buf length:sizeof(sig_buf)];
    //[sign writeToFile:smoutPaths atomically:NO];

    NSLog(@" sign : %s" , sign);

    /* signing */
    CMS_ContentInfo *ci = CMS_sign(cert, pkey, NULL, dataforsign, CMS_BINARY | CMS_NOSMIMECAP); //With source data attach
    ////    CMS_ContentInfo *ci = CMS_sign(key_cert, key, extra_certs, data, CMS_BINARY | CMS_NOSMIMECAP | CMS_DETACHED); // Without attached source data
//    SMIME_write_CMS(out, ci, dataforsign, flags);
    //[self.txtCMS setText:[NSString stringWithUTF8String: sig_buf]];
    if(!ci) {
        NSLog(@"error coult not create signing structure");
    }

    NSLog(@"CMS: %s" , ci);
    
    NSString *content = [NSString stringWithContentsOfFile:filePath
                                                  encoding:NSASCIIStringEncoding
                                                     error:NULL];
    // maybe for debugging...
    
//    NSLog(@"contents: %@", content);
    
    NSRange   searchedRange = NSMakeRange(0, [content length]);
    NSString *pattern = @"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$";
 
    
    NSRegularExpression* regex = [NSRegularExpression regularExpressionWithPattern: pattern   options:NSRegularExpressionAnchorsMatchLines error:&error];
    NSArray* matches = [regex matchesInString:content options:0 range: searchedRange];
    NSLog(@"matches: %@", matches);
    NSString *string = @"";
    NSMutableString *signature = [NSMutableString string];
    for (NSTextCheckingResult* match in matches) {
        NSString* matchText = [content substringWithRange:[match range]];
//        NSLog(@"match: %@", matchText);
        [signature appendString:matchText];
        if([matchText hasSuffix:@"=="]){
            break;
        }
//        NSLog(@"match: %@", matchText);
//        NSRange group1 = [match rangeAtIndex:1];
//        NSRange group2 = [match rangeAtIndex:2];
//        NSLog(@"group1: %@", [content substringWithRange:group1]);
//        NSLog(@"group2: %@", [content substringWithRange:group2]);
    }
    
//    NSString* fullPath = [smoutPaths stringByExpandingTildeInPath];
//    NSURL* fileUrl = [NSURL fileURLWithPath:fullPath];
//    //NSURLRequest* fileUrlRequest = [[NSURLRequest alloc] initWithURL:fileUrl];
//    NSURLRequest* fileUrlRequest = [[NSURLRequest alloc] initWithURL:fileUrl cachePolicy:NSURLCacheStorageNotAllowed timeoutInterval:.1];
//
//    NSError* error = nil;
//    NSURLResponse* response = nil;
//    NSData* fileData = [NSURLConnection sendSynchronousRequest:fileUrlRequest returningResponse:&response error:&error];
    
    
//    fileData; // Ignore this if you're using the timeoutInterval
    // request, since the data will be truncated.
    
//    NSString* mimeType = [response MIMEType];
    
//    [fileUrlRequest release];
    
//    NSLog(@"RESPONSE: %s" , mimeType);

    const int SIZE = 1024;
    unsigned char *temp = malloc(SIZE);
    memset(temp, 0, SIZE);

    //Check certificate Dates
    BIO *b = BIO_new(BIO_s_mem());

    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);

    ASN1_TIME_print(b, not_before);
    BIO_read(b, temp, SIZE);
    memset(temp, 0, SIZE);

    time_t not_before_t = ASN1_GetTimeT(not_before);

    ASN1_TIME_print(b, not_after);
    BIO_read(b, temp, SIZE);
    memset(temp, 0, SIZE);
    time_t not_after_t = ASN1_GetTimeT(not_after);
    free(temp);
    

    //Check certificate dates
    if(difftime(time(NULL), not_before_t) < 0) {
        NSLog(@"Certificate not_before problem");
        goto errorlabels;
    } else if(difftime(time(NULL), not_after_t) > 0) {
        NSLog(@"Certificate valid period expired");
        goto errorlabels;
    }
    
    


    NSLog(@"done");

errorlabels:

    CMS_ContentInfo_free(ci);
//
    BIO_free(dataforsign);
    ERR_print_errors_fp(stderr);
//
    ERR_remove_state(/* pid= */ 0);
//    ENGINE_cleanup();
    CONF_modules_unload(/* all= */ 1);
// //    EVP_cleanup();
//    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
    NSLog(@"generate signature pkcs11 complete!!!");
    
    EVP_PKEY_free(pkey);
    X509_free(cert);
    ERR_free_strings();
//    EVP_cleanup(); //вызываем только, когда абсолютно все завершили
    //  callback(@[[NSNull null], [NSNumber numberWithInt:(1*2)]]);
    //callback(@[[NSNull null], [NSString stringWithUTF8String:pem], paths ]);
    NSString *result = [NSString stringWithString:signature];
    callback(@[result]);
}


@end
