
#import <Cordova/CDV.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>

#define PUBLIC_KEY_TAG @"com.hitrust.hibank.publickey"

typedef NSMutableDictionary JSONObject;
typedef NSMutableArray      JSONArray;

@interface E2EE : CDVPlugin {
    NSMutableData *challengeValue;
    NSMutableData *sessionKeyValue;
    NSString *clientSessionId;
}
@end

@implementation E2EE

- (void)echo:(CDVInvokedUrlCommand*)command
{
    id message = [command.arguments objectAtIndex:0];
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:message];

    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)echoAsyncHelper:(NSArray*)args
{
    [self.commandDelegate sendPluginResult:[args objectAtIndex:0] callbackId:[args objectAtIndex:1]];
}

- (void)echoAsync:(CDVInvokedUrlCommand*)command
{
    id message = [command.arguments objectAtIndex:0];
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:message];

    [self performSelector:@selector(echoAsyncHelper:) withObject:[NSArray arrayWithObjects:pluginResult, command.callbackId, nil] afterDelay:0];
}

/*
 * 產生 Challenge
 */
-(void) generateChallenge:(CDVInvokedUrlCommand*)command {
    challengeValue = [NSMutableData dataWithLength:16];
    int result = SecRandomCopyBytes(kSecRandomDefault, 16, challengeValue.mutableBytes);
    JSONObject *challengeObj;
    if (result == noErr) {
        NSString *value = [challengeValue base64EncodedStringWithOptions:kNilOptions];
        challengeObj = [[JSONObject alloc] init];
        [challengeObj setObject:value forKey:@"clientChallenge"];
    }
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:challengeObj];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

/*
 * 驗證 Response
 */
-(void) verifyResponse:(CDVInvokedUrlCommand*)command {
    JSONObject *resObj = [[JSONObject alloc] init];
    JSONObject *serverResObj = command.arguments[0];
    NSString *serverChallenge = [serverResObj valueForKey:@"serverChallenge"];
    NSString *serverPublicKey = [serverResObj valueForKey:@"publicKey"];
    NSString *serverResponse = [serverResObj valueForKey:@"serverResponse"];
    NSData *response = [[NSData alloc] initWithBase64EncodedString:serverResponse options:0];
    NSData *check = [self response:challengeValue];
    if ([response isEqualToData:check]) {
        clientSessionId = [serverResObj valueForKey:@"clientSessionId"];
        NSString *sessionKey = [self generateSessionKey:serverPublicKey];
        if (sessionKey) {
            NSString *clientResponse = [self calculateResponse:serverChallenge];
            [resObj setObject:sessionKey forKey:@"sessionKey"];
            [resObj setObject:clientResponse forKey:@"clientResponse"];
        }
    }
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:resObj];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

/*
 * 使用 SessionKey 解密
 */
-(void) sessionKeyDecrypt:(CDVInvokedUrlCommand*)command {
    NSString *cipherText = command.arguments[0];
    NSData *cipherTextData = [[NSData alloc] initWithBase64EncodedString:cipherText options:0];
    NSData *plainTextData = [self AES_Process:kCCDecrypt key:sessionKeyValue input:cipherTextData length:cipherTextData.length];
    NSString *plainText = [NSString stringWithUTF8String:plainTextData.bytes];
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:plainText];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

/*
 * 使用 SessionKey 加密
 */
-(void) sessionKeyEncrypt:(CDVInvokedUrlCommand*)command {
    NSString *plainText = command.arguments[0];
    NSData *plainTextData = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    NSData *cipherData = [self AES_Process:kCCEncrypt key:sessionKeyValue input:plainTextData length:plainTextData.length];
    NSString *B64CipherText = [cipherData base64EncodedStringWithOptions:0];
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:B64CipherText];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (NSData*) AES_Process:(CCOperation)operation key:(NSData*)keyData input:(NSData*)inputDara length:(size_t)inputLength{
    size_t outputLength;
    size_t blockSize = [keyData length];
    if (operation == kCCEncrypt){
        outputLength = blockSize * (inputLength/blockSize + (inputLength%blockSize>=0));
    }else{
        outputLength = inputLength;
    }
    
    NSMutableData *outputData = [NSMutableData dataWithLength:outputLength];
    
    size_t numProcessed = 0;
    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kCCAlgorithmAES,
                                          kCCOptionECBMode | kCCOptionPKCS7Padding,
                                          keyData.bytes, [keyData length],
                                          NULL,                     /* initialization vector (optional) */
                                          inputDara.bytes,          /* input */
                                          inputLength,              /* input length */
                                          outputData.mutableBytes,  /* output */
                                          outputData.length,        /* output length */
                                          &numProcessed);
    return [outputData subdataWithRange:NSMakeRange(0, numProcessed)];;
}

//----------------------------------------------------------------------------------------------------

-(NSString *) calculateResponse:(NSString *) challengeB64 {
    NSData *challengeData = [[NSData alloc] initWithBase64EncodedString:challengeB64 options:0];
    NSData *responseData = [self response:challengeData];
    NSString *base64String = [responseData base64EncodedStringWithOptions:0];
    return base64String;
}

-(NSData *) response:(NSData *) challenge {
    uint8_t secret[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    NSMutableData *challengeData = [[NSMutableData alloc] init];
    [challengeData appendData:challenge];
    [challengeData appendData:[NSData dataWithBytes:secret length:sizeof(secret)]];
    //
    uint8_t digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(challengeData.bytes, (CC_LONG)challengeData.length, digest);
    NSData *resultData = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
    return resultData;
}

-(NSString *) generateSessionKey:(NSString *) x509B64 {
    sessionKeyValue = [NSMutableData dataWithLength:32];
    int result = SecRandomCopyBytes(kSecRandomDefault, 32, sessionKeyValue.mutableBytes);
    NSString *retValue = nil;
    if (result == noErr) {
        SecKeyRef publicKey = [self addPublicKey:x509B64 withTag:PUBLIC_KEY_TAG];
        if (publicKey != nil) {
            size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
            uint8_t *cipherBuffer = malloc(cipherBufferSize);
            OSStatus status = SecKeyEncrypt(publicKey,
                                            kSecPaddingPKCS1,
                                            sessionKeyValue.mutableBytes,
                                            32,
                                            cipherBuffer,
                                            &cipherBufferSize);
            if (status == noErr) {
                NSData *encryptedData = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
                retValue = [encryptedData base64EncodedStringWithOptions:(NSDataBase64EncodingOptions)0];
            }
            free(cipherBuffer);
        }
    }
    return retValue;
}

- (NSData *)stripPublicKeyHeader:(NSData *)d_key
{
    // Skip ASN.1 public key header
    if (d_key == nil) return(nil);
    
    unsigned long len = [d_key length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int  idx    = 0;
    
    if (c_key[idx++] != 0x30) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    // PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] =
    { 0x30,   0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00 };
    if (memcmp(&c_key[idx], seqiod, 15)) return(nil);
    
    idx += 15;
    
    if (c_key[idx++] != 0x03) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    if (c_key[idx++] != '\0') return(nil);
    
    // Now make a new NSData from this buffer
    return([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}

- (SecKeyRef)addPublicKey:(NSString *)key withTag:(NSString *)tag
{
    NSRange spos = [key rangeOfString:@"-----BEGIN PUBLIC KEY-----"];
    NSRange epos = [key rangeOfString:@"-----END PUBLIC KEY-----"];
    if(spos.location != NSNotFound && epos.location != NSNotFound){
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e-s);
        key = [key substringWithRange:range];
    }
    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    // This will be base64 encoded, decode it.
    //NSData *d_key = [GTMBase64 decodeString:key];
    NSData *d_key = [[NSData alloc] initWithBase64EncodedString:key options:0];
    //NSLog(@"key data:\n%@\n", BytesToHexString(d_key));
    
    d_key = [self stripPublicKeyHeader:d_key];
    if (d_key == nil) return(FALSE);
    
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
    [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    OSStatus secStatus = SecItemDelete((__bridge CFDictionaryRef)publicKey);
    
    CFTypeRef persistKey = nil;
    
    // Add persistent version of the key to system keychain
    [publicKey setObject:d_key forKey:(__bridge id)kSecValueData];
    [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id) kSecAttrKeyClass];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id) kSecReturnPersistentRef];
    
    secStatus = SecItemAdd((__bridge CFDictionaryRef)publicKey, &persistKey);
    if (persistKey != nil) CFRelease(persistKey);
    
    if ((secStatus != noErr) && (secStatus != errSecDuplicateItem)) {
        return(FALSE);
    }
    
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    
    [publicKey removeObjectForKey:(__bridge id)kSecValueData];
    [publicKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    secStatus = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey,
                                    (CFTypeRef *)&keyRef);
    
    return keyRef;
}
    
@end
