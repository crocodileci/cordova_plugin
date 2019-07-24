//
//  HTSmartCard.m
//  HTSmartCard
//
//  Created by Joe on 2019/7/18.
//  Copyright © 2019 HiTrust. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "HTSmartCard.h"
#import "HTSmartCardUtility.h"

@implementation NSString (Hex)

+ (NSString*) hexStringWithData: (unsigned char*) data ofLength: (NSUInteger) len
{
    NSMutableString *tmp = [NSMutableString string];
    for (NSUInteger i=0; i<len; i++)
        [tmp appendFormat:@"%02x", data[i]];
    return [NSString stringWithString:tmp];
}

+ (NSString *) hexToString:(NSString *) hexStr {
    NSMutableString * newString = [[NSMutableString alloc] init];
    int i = 0;
    while (i < [newString length])
    {
        NSString * hexChar = [newString substringWithRange: NSMakeRange(i, 2)];
        int value = 0;
        sscanf([hexChar cStringUsingEncoding:NSASCIIStringEncoding], "%x", &value);
        [newString appendFormat:@"%c", (char)value];
        i+=2;
    }
    return [NSString stringWithString:newString];
}

@end

@implementation HTSmartCard

HTSmartCardUtility scardUtil;

-(id) init {
    if (self = [super init]) {
        cardHandle = -1;
        readerName = nil;
        readerIsAttached = NO;
        cardIsAttached = NO;
        SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &cardContext);
    }
    return self;
}

-(void) readerInterfaceDidChange:(BOOL)attached {
    readerIsAttached = attached;
    if (attached) {
        SCReader scReaders;
        LONG retCode = scardUtil.ListReaders(&scReaders);
        if (retCode == SCARD_S_SUCCESS && scReaders.Count != 0) {
            readerName = [NSString stringWithUTF8String:scReaders.Name[0]];
        }
    } else {
        readerName = nil;
    }
}

-(void) cardInterfaceDidDetach:(BOOL)attached {
    cardIsAttached = attached;
    if (attached) {
        LONG retCode;
        if (readerName == nil || readerName.length == 0) {
            SCReader scReaders;
            retCode = scardUtil.ListReaders(&scReaders);
            if (retCode == SCARD_S_SUCCESS && scReaders.Count != 0) {
                readerName = [NSString stringWithUTF8String:scReaders.Name[0]];
            }
        }
        if (readerName != nil && readerName.length != 0) {
            ReaderAttr readerAttr;
            retCode = scardUtil.ConnectCard([readerName UTF8String], &cardHandle, &readerAttr);
        }
    } else {
        scardUtil.DisconnectCard(cardHandle, DISCONN_UNPOWRR);
        cardHandle = -1;
    }
}

/*
 * 功能 : echo
 * 輸入 : message -
 * 輸出 : JSONObject
 */
-(JSONObject *) echo:(NSString *)message {
    JSONObject *jsonObj = [[JSONObject alloc] init];
    [jsonObj setObject:[NSNumber numberWithLong:SCARD_S_SUCCESS] forKey:KEY_RET_CODE];
    [jsonObj setObject:message forKey:KEY_RESULT];
    return jsonObj;
}

/*
 * 功能 : 檢查讀卡機是否存在
 * 輸入 : 無
 * 輸出 : 使用success傳回結果為true: 存在, false: 不存在
 */
-(BOOL) isReaderExisted {
    return readerIsAttached;
}

/**
 * 功能 : 檢查卡片是否存在
 * 輸入 : 無
 * 輸出 : 使用success傳回結果為boolen, true: 存在, false: 不存在
 */
-(BOOL) isCardExisted {
    return cardIsAttached;
}

/**
 * 功能 : 讀取卡片資訊
 * 輸入 : 無
 * 輸出 : 使用success傳回結果 object, {issuer:, mainAccount:}
 */
-(JSONObject *) getCardInfo {
    JSONObject *jsonObj = [[JSONObject alloc] init];
    LONG retCode;
    if (readerIsAttached && cardIsAttached) {
        CardBaseProfile cardProfile;
        memset(&cardProfile, 0, sizeof(cardProfile));
        ULONG swCode;
        retCode = scardUtil.GetCardBaseProfile(cardHandle, &cardProfile, &swCode);
        if (retCode == SCARD_S_SUCCESS && swCode == SW_CODE_SUCCESS) {
            if (cardProfile.AccountCount > 0) {
                NSString *issuerNo = [NSString stringWithUTF8String:cardProfile.IssuerNo];
                NSString *account = [NSString stringWithUTF8String:cardProfile.Accounts[0]];
                [jsonObj setObject:issuerNo forKey:@"issuer"];
                [jsonObj setObject:account forKey:@"mainAccount"];
            }
        } else {
            if (retCode == SCARD_S_SUCCESS && swCode != SW_CODE_SUCCESS)
                retCode = swCode;
        }
    } else {
        retCode = SCARD_E_NOT_READY;
    }
    [jsonObj setObject:[NSNumber numberWithLong:retCode] forKey:KEY_RET_CODE];
    
    return jsonObj;
}

/**
 * 功能 : 取得TAC值
 * 輸入 : text -
 * 輸出 : 使用success傳回結果 object, {tac:, serial:}
 */
-(JSONObject *) getTAC:(NSString *)text {
    JSONObject *jsonObj = [[JSONObject alloc] init];
    LONG retCode;
    
    if ([text isKindOfClass:[NSNull class]])
        text = nil;
    
    if (text != nil && text.length != 0) {
        if (readerIsAttached && cardIsAttached) {
            ULONG swCode;
            NSMutableData *tacData = [[NSMutableData alloc] init];
            [tacData setData:[text dataUsingEncoding:NSUTF8StringEncoding]];
            //壓製交易驗證碼及交易序號
            const u_char EFID[] = {0x10, 0x80};
            u_char snum[16] = {0}, tac[16] = {0};
            int snum_len = 16, tac_len = 16;
            retCode = scardUtil.WriteRecordWithSNUMTAC(cardHandle, EFID, (u_char*)tacData.bytes, tacData.length, snum, &snum_len, tac, &tac_len, &swCode);
            if (retCode == SCARD_S_SUCCESS && swCode == SW_CODE_SUCCESS) {
                NSString *snumStr = [NSString stringWithCString:(char *)snum encoding:NSUTF8StringEncoding];
                NSString *hexTac = [NSString hexStringWithData:tac ofLength:16];
                [jsonObj setObject:snumStr forKey:@"serial"];
                [jsonObj setObject:hexTac forKey:@"tac"];
            } else {
                if (retCode == SCARD_S_SUCCESS && swCode != SW_CODE_SUCCESS)
                    retCode = swCode;
            }
        } else {
            retCode = SCARD_E_NOT_READY;
        }
    } else {
        retCode = SCARD_E_INVALID_PARAMETER;
    }
    [jsonObj setObject:[NSNumber numberWithLong:retCode] forKey:KEY_RET_CODE];
    
    return jsonObj;
}

/**
 * 功能 : 驗證密碼
 * 輸入 : pincode - 密碼
 * 輸出 : 使用success傳回結果 Boolean, true: 驗證成功, false: 驗證失敗
 */
-(BOOL) verifyPin:(NSString *)pincode {
    BOOL success = NO;
    LONG retCode;
    
    if ([pincode isKindOfClass:[NSNull class]])
        pincode = nil;
    
    if (pincode != nil && pincode.length != 0) {
        if (readerIsAttached && cardIsAttached) {
            ULONG swCode;
            retCode = scardUtil.VerifyPIN(cardHandle, [pincode UTF8String], &swCode);
            if (retCode == SCARD_S_SUCCESS && swCode == SW_CODE_SUCCESS) {
                success = YES;
            } else {
                if (retCode == SCARD_S_SUCCESS && swCode != SW_CODE_SUCCESS)
                    retCode = swCode;
            }
        } else {
            retCode = SCARD_E_NOT_READY;
        }
    } else {
        retCode = SCARD_E_INVALID_PARAMETER;
    }
    return success;
}

/**
 * 功能 : 變更密碼
 * 輸入 : pincodeOrg - 舊密碼
 *       pincodeNew - 新密碼
 * 輸出 : 使用success傳回結果 Boolen, true: 驗證成功, false: 變更失敗
 */
-(BOOL) modifyPin:(NSString *)pincodeOrg withPincodeNew:(NSString *)pincodeNew {
    BOOL success = NO;
    LONG retCode;
    
    if ([pincodeOrg isKindOfClass:[NSNull class]])
        pincodeOrg = nil;
    if ([pincodeNew isKindOfClass:[NSNull class]])
        pincodeNew = nil;
    
    if (pincodeOrg != nil && pincodeOrg.length != 0 && pincodeNew != nil && pincodeNew.length != 0) {
        if (readerIsAttached && cardIsAttached) {
            ULONG swCode;
            retCode = scardUtil.VerifyPIN(cardHandle, [pincodeOrg UTF8String], &swCode);
            if (retCode == SCARD_S_SUCCESS && swCode == SW_CODE_SUCCESS) {
                retCode = scardUtil.ChangePIN(cardHandle, [pincodeNew UTF8String], &swCode);
                if (retCode == SCARD_S_SUCCESS && swCode == SW_CODE_SUCCESS) {
                    success = YES;
                } else {
                    if (retCode == SCARD_S_SUCCESS && swCode != SW_CODE_SUCCESS)
                        retCode = swCode;
                }
            } else {
                if (retCode == SCARD_S_SUCCESS && swCode != SW_CODE_SUCCESS)
                    retCode = swCode;
            }
        } else {
            retCode = SCARD_E_NOT_READY;
        }
    } else {
        retCode = SCARD_E_INVALID_PARAMETER;
    }
    return success;
}

@end
