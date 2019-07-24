#import "CardReader.h"

@implementation CardReader

- (void)pluginInitialize {
    reader = [[ReaderInterface alloc]init];
    [reader setDelegate:self];
    self.smartCard = [[HTSmartCard alloc] init];
}

#pragma mark ReaderInterfaceDelegate Methods

- (void) readerInterfaceDidChange:(BOOL)attached
{
    [self.smartCard readerInterfaceDidChange:attached];
    if (attached) {
        if (callbackId != nil) {
            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"readerattached"];
            [pluginResult setKeepCallbackAsBool:YES];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:callbackId];
        }
    } else {
        if (callbackId != nil) {
            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"readerdetached"];
            [pluginResult setKeepCallbackAsBool:YES];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:callbackId];
        }
    }
}

- (void) cardInterfaceDidDetach:(BOOL)attached
{
    [self.smartCard cardInterfaceDidDetach:attached];
    if (attached) {
        if (callbackId != nil) {
            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"cardattached"];
            [pluginResult setKeepCallbackAsBool:YES];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:callbackId];
        }
    } else {
        if (callbackId != nil) {
            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"carddetached"];
            [pluginResult setKeepCallbackAsBool:YES];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:callbackId];
        }
    }
}

- (void) echo:(CDVInvokedUrlCommand*)command {
    NSString *message = @"";
    if (command.arguments != nil) {
        if (command.arguments.count > 0)
            message = command.arguments[0];
    }
    JSONObject *jobj = [self.smartCard echo:message];
    long retCode = [[jobj valueForKey:KEY_RET_CODE] longLongValue];
    
    CDVPluginResult* pluginResult = nil;
    if (retCode == SC_SUCCESS) {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:jobj];
    } else {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:jobj];
    }
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    
    if (callbackId != nil) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"readerattached"];
        [pluginResult setKeepCallbackAsBool:YES];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:callbackId];
    }
}

- (void) isReaderExisted:(CDVInvokedUrlCommand*)command {
    BOOL existed = [self.smartCard isReaderExisted];
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:existed];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void) isCardExisted:(CDVInvokedUrlCommand *)command {
    BOOL existed = [self.smartCard isCardExisted];
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:existed];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void) getCardInfo:(CDVInvokedUrlCommand *)command {
    JSONObject *jobj = [self.smartCard getCardInfo];
    long retCode = [[jobj valueForKey:KEY_RET_CODE] longLongValue];
    
    CDVPluginResult* pluginResult = nil;
    if (retCode == SC_SUCCESS) {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:jobj];
    } else {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:jobj];
    }
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void) getTAC:(CDVInvokedUrlCommand *)command {
    NSString *text = @"";
    if (command.arguments != nil) {
        if (command.arguments.count > 0)
            text = command.arguments[0];
    }

    JSONObject *jobj = [self.smartCard getTAC:text];
    long retCode = [[jobj valueForKey:KEY_RET_CODE] longLongValue];
    
    CDVPluginResult* pluginResult = nil;
    if (retCode == SC_SUCCESS) {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:jobj];
    } else {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:jobj];
    }
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void) verifyPin:(CDVInvokedUrlCommand *)command {
    NSString *pincode = @"";
    if (command.arguments != nil) {
        if (command.arguments.count > 0)
            pincode = command.arguments[0];
    }
    BOOL success = [self.smartCard verifyPin:pincode];
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:success];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void) modifyPin:(CDVInvokedUrlCommand *)command {
    NSString *pincodeOrg = @"";
    NSString *pincodeNew = @"";
    if (command.arguments != nil) {
        if (command.arguments.count > 0)
            pincodeOrg = command.arguments[0];
        if (command.arguments.count > 1)
            pincodeNew = command.arguments[1];
    }
    
    BOOL success = [self.smartCard modifyPin:pincodeOrg withPincodeNew:pincodeNew];
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:success];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void) eventHandler:(CDVInvokedUrlCommand *)command {
    callbackId = command.callbackId;
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_NO_RESULT];
    [pluginResult setKeepCallbackAsBool:YES];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

@end
