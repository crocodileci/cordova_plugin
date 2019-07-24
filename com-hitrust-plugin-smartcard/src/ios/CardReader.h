#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Cordova/CDVPlugin.h>
#import "HTSmartCard.h"
#import "ReaderInterface.h"

@interface CardReader : CDVPlugin <ReaderInterfaceDelegate>{
    ReaderInterface *reader;
    NSString *callbackId;
}

@property HTSmartCard *smartCard;

- (void) echo:(CDVInvokedUrlCommand *)command;
- (void) isReaderExisted:(CDVInvokedUrlCommand *)command;
- (void) isCardExisted:(CDVInvokedUrlCommand *)command;
- (void) getCardInfo:(CDVInvokedUrlCommand *)command;
- (void) getTAC:(CDVInvokedUrlCommand *)command;
- (void) verifyPin:(CDVInvokedUrlCommand *)command;
- (void) modifyPin:(CDVInvokedUrlCommand *)command;
- (void) eventHandler:(CDVInvokedUrlCommand *)command;

@end
