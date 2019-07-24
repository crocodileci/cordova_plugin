//
//  HTSmartCardUtility.h
//
//  Created by Austin on 2017/11/24.
//  Copyright © 2017年 HiTRUST. All rights reserved.
//

#ifndef HTSmartCardUtility_h
#define HTSmartCardUtility_h

#include <stdio.h>
#include "winscard.h"

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#define SW_CODE_SUCCESS                             0X9000
#define SW_CODE_UNDEFINED_ERROR_6600                0X6600
#define SW_CODE_INCOHERENT_PARAMETERS_OR_DATA       0X6601
#define SW_CODE_ADDRESSING_OR_REFERENCING_PROBLEM   0X6602
#define SW_CODE_MEMORY_CAPACITY_PROBLEM             0X6604
#define SW_CODE_SECURITY_PROBLEM                    0X6608
#define SW_CODE_SECURITY_STATUS_NOT_CORRECT         0X6610
#define SW_CODE_LOCKED_SITUATION                    0X6620
#define SW_CODE_SYSTEM_DATA_PROBLEM                 0X6640
#define SW_CODE_EXECUTION_NOT_ALLOWED               0X6660
#define SW_CODE_APDU_INCORRECT_OR_NOT_ACCEPTED      0X6700
#define SW_CODE_REFERENCE_ERROR                     0X6B00
#define SW_CODE_INSTRUCTION_ERROR                   0X6D00
#define SW_CODE_CLASS_ERROR                         0X6D00
#define SW_CODE_UNDEFINED_ERROR_6F00                0X6F00

#ifndef SCARD_INVALID_HANDLE
#define SCARD_INVALID_HANDLE    0
#endif

#define MAX_ISSUERNO_LEN    9
#define MAX_REMARKS_LEN     61
#define MAX_ACCOUNT         8
#define MAX_ACCOUNT_LEN     17

#define MAX_RECORD_BUFFER   128

typedef unsigned char BYTE;
typedef unsigned int  UINT;

typedef struct {
    UINT                State;
    UINT                Protocol;
    UINT                Len;
    BYTE                Atr[128];
} ReaderAttr;

typedef struct {
    char	Name[128][10];
    int		Count;
} SCReader;

typedef struct {
    char IssuerNo[MAX_ISSUERNO_LEN];
    BYTE IssuerNoLen;
    char Remarks[MAX_REMARKS_LEN];
    BYTE RemarksLen;
    char Accounts[MAX_ACCOUNT][MAX_ACCOUNT_LEN];
    BYTE AccountsLen[MAX_ACCOUNT];
    BYTE AccountCount;
} CardBaseProfile;

typedef enum{
    STATUS_CARD_PRESENT,
    STATUS_CARD_ABSENT,
    STATUS_OTHERS
} CardStatus;

typedef enum{
    RID_ISSUE_NO    = 0x01,
    RID_ICC_REMARK  = 0x02,
    RID_ACCOUNT     = 0x03,
} EF1001_RID;

typedef enum{
    DISCONN_DEFAULT     = SCARD_LEAVE_CARD,
    DISCONN_LEAVE_CARD  = SCARD_LEAVE_CARD,
    DISCONN_RESET_CARD  = SCARD_RESET_CARD,
    DISCONN_UNPOWRR     = SCARD_UNPOWER_CARD,
    DISCONN_EJECT_CARD  = SCARD_EJECT_CARD
} DisconnectType;

typedef enum{
    RESET_DEFAULT     = SCARD_LEAVE_CARD,
    RESET_LEAVE_CARD  = SCARD_LEAVE_CARD,
    RESET_RESET_CARD  = SCARD_RESET_CARD,
    RESET_UNPOWRR     = SCARD_UNPOWER_CARD,
} ResetType;

class HTSmartCardUtility
{
    
private:
    SCARDCONTEXT        mContext;
    SCARD_IO_REQUEST    *mSCardPCI;
    
    BYTE    mSendBuffer[256];
    BYTE    mRecvBuffer[256];
    UINT    mSendLength;
    UINT    mRecvLength;

public:
    
    HTSmartCardUtility();
    ~HTSmartCardUtility();
    
    __attribute__((deprecated))  ULONG InitSmartCardContext();
    __attribute__((deprecated))  ULONG ReleaseSmartCardContext();
    
    ULONG ListReaders(OUT SCReader *stReaderInfo);
    ULONG GetReaderStatus(IN  SCARDHANDLE hCard,
                          IN  UINT        dwAttrId,
                          OUT BYTE        *pbAttr,
                          IN OUT UINT     *pcbAttrLen);
    ULONG GetCardStatus(IN SCARDHANDLE	hCard, IN const char *ReaderName, OUT ReaderAttr *stATR);
    ULONG CheckCardInsert(IN const char *ReaderName, OUT CardStatus *card_status);
    ULONG ConnectCard(IN const char *ReaderName, OUT SCARDHANDLE *hCard, OUT ReaderAttr *stATR);
    ULONG DisconnectCard(IN SCARDHANDLE	hCard, IN DisconnectType type);
    
    ULONG ReconnectCard(IN	SCARDHANDLE		hCard,
                        IN	const char		*ReaderName,
                        IN  ResetType       type,
                        OUT ReaderAttr		*stATR);

    ULONG VerifyPIN(IN SCARDHANDLE      hCard,
                    IN const char       *card_pin,
                    OUT ULONG           *sw_code);
    
    ULONG ChangePIN(IN SCARDHANDLE      hCard,
                    IN const char       *new_pin,
                    OUT ULONG           *sw_code);
    
    ULONG GetIssuerID(IN SCARDHANDLE hCard,
                      OUT char       *IssuerID,
                      OUT ULONG      *sw_code);
    
    ULONG GetMainAccount(IN SCARDHANDLE hCard,
                         OUT char       *account,
                         OUT ULONG      *sw_code);
    
    ULONG GetAllAccount(IN SCARDHANDLE hCard,
                        OUT char       accounts[MAX_ACCOUNT][MAX_ACCOUNT_LEN],
                        OUT ULONG      *sw_code);
    
    ULONG GetCardBaseProfile(IN  SCARDHANDLE        hCard,
                             OUT CardBaseProfile  *profile,
                             OUT ULONG              *sw_code);
    
    ULONG WriteRecordWithSNUMTAC(IN   SCARDHANDLE   hCard,
                                 IN   const BYTE    *EFID,
                                 IN   const BYTE    *transData,
                                 IN   BYTE          transDataLen,
                                 OUT  BYTE          *SNum,
                                 OUT  int           *SNumLen,
                                 OUT  BYTE          *TAC,
                                 OUT  int           *TACLen,
                                 OUT  ULONG         *sw_code);
    
    int hex2bin(IN  const char *hex, IN  size_t hex_len, IN OUT BYTE *bin);
    int bin2hex(IN  const BYTE* bin, IN  size_t bin_len, IN OUT char* hex);
    
private:
    
    ULONG SelectAID(IN SCARDHANDLE hCard, OUT ULONG *sw_code);
    
    ULONG SelectEF(IN   SCARDHANDLE hCard,
                   IN   BYTE        *EFID,
                   OUT  ULONG       *sw_code);
    
    ULONG ReadSigleRecord(IN   SCARDHANDLE hCard,
                          IN   BYTE        RecordID,
                          OUT  BYTE        *RecordData,
                          OUT  ULONG       *sw_code);
    
    ULONG ReadAllRecord(IN   SCARDHANDLE  hCard,
                        IN   BYTE         begin_id,
                        OUT  BYTE         *RecordData,
                        OUT  ULONG        *sw_code);
    
    
    
};

#endif /* HTSmartCardUtility_h */
