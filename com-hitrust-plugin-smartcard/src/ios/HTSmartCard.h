//
//  HTSmartCard.h
//  HTSmartCard
//
//  Created by Joe on 2019/7/18.
//  Copyright © 2019 HiTrust. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "winscard.h"
#import "ft301u.h"

FOUNDATION_EXPORT double HTSmartCardVersionNumber;
FOUNDATION_EXPORT const unsigned char HTSmartCardVersionString[];

typedef NSMutableDictionary JSONObject;
typedef NSMutableArray      JSONArray;

#define SC_SUCCESS      0

#define KEY_RESULT      @"result"
#define KEY_NAME        @"name"
#define KEY_RET_CODE    @"ret_code"

typedef void (^CompletionBlock)(int error, JSONObject *jsonObject);

@interface HTSmartCard : NSObject {
    SCARDCONTEXT cardContext;
    SCARDHANDLE cardHandle;
    NSString *readerName;
    BOOL readerIsAttached;
    BOOL cardIsAttached;
}

-(void) readerInterfaceDidChange:(BOOL)attached;
-(void) cardInterfaceDidDetach:(BOOL)attached;

-(JSONObject *) echo:(NSString *)message;
-(BOOL) isReaderExisted;
-(BOOL) isCardExisted;
-(JSONObject *) getCardInfo;
-(JSONObject *) getTAC:(NSString *)text;
-(BOOL) verifyPin:(NSString *)pincode;
-(BOOL) modifyPin:(NSString *)pincodeOrg withPincodeNew:(NSString *)pincodeNew;

@end
