//
//  HTSmartCardUtility.cpp
//
//  Created by hitrustmac on 2017/11/24.
//  Copyright © 2017年 HiTRUST. All rights reserved.
//

#include "HTSmartCardUtility.h"

#include <ctype.h>
#include <time.h>
#include <stdlib.h>
#include <memory.h>

#define	BUFFER_SIZE 4096

#pragma mark Inline Method Header

static inline ULONG Initialize(SCARDCONTEXT *context);
static inline ULONG Finalize(SCARDCONTEXT *context);
static inline ULONG SendAPDU(IN  SCARDHANDLE            hCard,
                             IN  SCARD_IO_REQUEST       *send_pci,
                             IN  const unsigned char    *send_buffer,
                             IN  unsigned int           send_length,
                             OUT unsigned char          *recv_buffer,
                             OUT unsigned int           *recv_length);
static inline ULONG GetSWCode(IN OUT unsigned char *recv_buffer,
                              IN OUT unsigned int  *recv_length);

#pragma mark Class Methods

HTSmartCardUtility::HTSmartCardUtility()
{
    printf("HTSmartCardUtility()\n");
    mContext = SCARD_INVALID_HANDLE;
    mSCardPCI = SCARD_PCI_T1;
    Initialize(&mContext);
}

HTSmartCardUtility::~HTSmartCardUtility()
{
    printf("~HTSmartCardUtility()\n");
    if(mContext){
        Finalize(&mContext);
    }
}
__attribute__((deprecated)) ULONG HTSmartCardUtility::InitSmartCardContext()
{
    return Initialize(&mContext);
}
__attribute__((deprecated)) ULONG HTSmartCardUtility::ReleaseSmartCardContext()
{
    return Finalize(&mContext);
}


/**
 取得所有的晶片卡讀卡機

 @param stReaderList 所有晶片卡讀卡機清單 (透過指標方式返回)
 @return 返回晶片卡錯誤代碼
 */
ULONG HTSmartCardUtility::ListReaders(OUT SCReader *stReaderList )
{
    BYTE i;
    char readers[BUFFER_SIZE] = {0};
    UINT readers_len = BUFFER_SIZE;
    
    memset(stReaderList, 0, sizeof(SCReader));

    //2.list reader and choice one
    UINT return_code = SCardListReaders(mContext, NULL, readers, &readers_len);
    
    if(return_code != SCARD_S_SUCCESS){
        return return_code;
    }
    
    //take out reader name into array
    i = 0;
    char* p = readers;
    while(*p)
    {
        size_t reader_len = strlen(p);
        memcpy(stReaderList->Name[i++], p, reader_len);
        stReaderList->Count = i;
        p += reader_len + 1;
    }
    
    return return_code;
}


/**
 取得晶片卡狀態

 @param hCard 晶片卡Handle
 @param ReaderName 欲使用(讀取)的讀卡機名稱
 @param stATR 晶片卡狀態屬性資料 (透過指標方式返回)
 @return 返回晶片卡錯誤代碼
 */
ULONG HTSmartCardUtility::GetCardStatus(IN  SCARDHANDLE	hCard,
                                        IN  const char  *ReaderName,
                                        OUT ReaderAttr	*stATR)
{
    BYTE atr[128] = {0};
    UINT atr_len = sizeof(atr);
    UINT state, protocol;
    char readers[BUFFER_SIZE]={0};
    UINT readers_len = BUFFER_SIZE;
    
    memcpy(readers, ReaderName, strlen(ReaderName));
    memset(stATR, 0x00, sizeof(ReaderAttr));
    
    UINT return_code = SCardStatus(hCard,
                                   readers,
                                   &readers_len,
                                   &state,
                                   &protocol,
                                   atr,
                                   &atr_len);
				
    
    if(return_code != SCARD_S_SUCCESS)
        return return_code;
    
    stATR->State = state;
    stATR->Protocol = protocol;
    
    switch (protocol)
    {
        case SCARD_PROTOCOL_T0:
            mSCardPCI = SCARD_PCI_T0;
            break;
        case SCARD_PROTOCOL_T1:
            mSCardPCI = SCARD_PCI_T1;
            break;
        case SCARD_PROTOCOL_RAW:
            mSCardPCI = SCARD_PCI_RAW;
            break;
        case SCARD_PROTOCOL_UNDEFINED:
        default:
            return SCARD_E_INVALID_VALUE;
    }
    
    return return_code;
}


/**
 檢查讀卡機中是否已插入晶片卡

 @param reader_name 欲檢查的讀卡機名稱
 @param card_status 晶片卡狀態 (透過指標方式返回)
 @return 返回晶片卡錯誤代碼
 */
ULONG HTSmartCardUtility::CheckCardInsert(IN const char *reader_name, OUT CardStatus *card_status)
{
    SCARD_READERSTATE ScardReaderState;
    
    ScardReaderState.szReader = reader_name;
    
    UINT return_code = SCARD_S_SUCCESS;
    
    ScardReaderState.dwCurrentState = SCARD_STATE_UNAWARE;
    return_code = SCardGetStatusChange(mContext, 0, &ScardReaderState, 1);
    if (return_code != SCARD_S_SUCCESS) {
        return return_code;
    }
    
    if(ScardReaderState.dwEventState & SCARD_STATE_PRESENT)
        *card_status = STATUS_CARD_PRESENT;  //  ic card exist
    else if(ScardReaderState.dwEventState & SCARD_STATE_EMPTY)
        *card_status = STATUS_CARD_ABSENT;   //  ic card not exist
    else
        *card_status = STATUS_OTHERS;       //other state
    
    return return_code;
}


/**
 連線讀卡機中的晶片卡

 @param readerName 要連線的讀卡機
 @param hCard 晶片卡連線的Handle (透過指標方式返回)
 @param readerAttr 讀卡機的屬性資料 (透過指標方式返回)
 @return 返回晶片卡錯誤代碼
 */
ULONG HTSmartCardUtility::ConnectCard(IN    const char  *readerName,
                                      OUT   SCARDHANDLE *hCard,
                                      OUT   ReaderAttr  *readerAttr)
                               
{
    
    UINT protocol, act_protocol;
    
    protocol = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;
    ULONG return_code = SCardConnect(mContext,
                                     readerName,
                                     SCARD_SHARE_EXCLUSIVE,
                                     protocol,
                                     hCard,
                                     &act_protocol);
    
    if(return_code != SCARD_S_SUCCESS)
        return return_code;
    
    switch (act_protocol)
    {
        case SCARD_PROTOCOL_T0:
            mSCardPCI = SCARD_PCI_T0;
            break;
        case SCARD_PROTOCOL_T1:
            mSCardPCI = SCARD_PCI_T1;
            break;
        case SCARD_PROTOCOL_RAW:
            mSCardPCI = SCARD_PCI_RAW;
            break;
        case SCARD_PROTOCOL_UNDEFINED:
        default:
            return SCARD_E_INVALID_VALUE;
    }

    return return_code;
}

/**
 中斷讀卡機中的晶片卡

 @param hCard 晶片卡連線的Handle
 @param type 中斷方式
 RESET_DEFAULT, DISCONN_DEFAULT, DISCONN_LEAVE_CARD, DISCONN_RESET_CARD, DISCONN_UNPOWRR, DISCONN_EJECT_CARD
 @return 返回晶片卡錯誤代碼
 */
ULONG HTSmartCardUtility::DisconnectCard(IN SCARDHANDLE hCard, IN DisconnectType type)
{
    return SCardDisconnect(hCard, type);
}


/**
  重新連線讀卡機中的晶片卡

 @param hCard 晶片卡連線的Handle
 @param ReaderName 晶片卡的讀卡機名稱
 @param type 重新連線方式
 RESET_DEFAULT, RESET_LEAVE_CARD, RESET_RESET_CARD, RESET_UNPOWRR
 @param stATR 晶片卡讀卡機屬性 (透過指標方式返回)
 @return 返回晶片卡錯誤代碼
 */
ULONG HTSmartCardUtility::ReconnectCard(IN	SCARDHANDLE		hCard,
                                        IN	const char		*ReaderName,
                                        IN  ResetType       type,
                                        OUT ReaderAttr		*stATR)
{
    UINT protocol, act_protocol;
    
    protocol = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;
    
    ULONG return_code = SCardReconnect(hCard,
                                       SCARD_SHARE_EXCLUSIVE,
                                       protocol,
                                       type,
                                       &act_protocol);

    if(return_code != SCARD_S_SUCCESS)
        return return_code;
    
    switch (act_protocol)
    {
        case SCARD_PROTOCOL_T0:
            mSCardPCI = SCARD_PCI_T0;
            break;
        case SCARD_PROTOCOL_T1:
            mSCardPCI = SCARD_PCI_T1;
            break;
        case SCARD_PROTOCOL_RAW:
            mSCardPCI = SCARD_PCI_RAW;
            break;
        case SCARD_PROTOCOL_UNDEFINED:
        default:
            return SCARD_E_INVALID_VALUE;
    }
    
    return return_code;
}


/**
 驗證晶片卡密碼

 @param hCard 晶片卡的Handle (CannectCard取得)
 @param card_pin 晶片卡密碼
 @param sw_code APDU SW錯誤代碼 (透過指標方式返回)
 @return 返回晶片卡錯誤代碼
 */
ULONG HTSmartCardUtility::VerifyPIN(IN SCARDHANDLE      hCard,
                                    IN const char       *card_pin,
                                    OUT ULONG           *sw_code)
{
    ULONG return_code = SCARD_S_SUCCESS;
    *sw_code = SW_CODE_SUCCESS;
    
    do
    {
        return_code = this->SelectAID(hCard, sw_code);
        if (return_code != SCARD_S_SUCCESS || *sw_code != 0x9000){
            break;
        }
        
        //  Clear buufer
        memset(mSendBuffer, 0, sizeof(mSendBuffer));
        memset(mRecvBuffer, 0, sizeof(mRecvBuffer));
        
        mSendBuffer[0] = 0x00;		//CLA	指令類別
        mSendBuffer[1] = 0x20;		//INS	指令碼
        mSendBuffer[2] = 0x00;		//P1	參數
        mSendBuffer[3] = 0x10;		//P2	參數
        mSendBuffer[4] = 0x08;		//Lc	Data長度(單位:Byte)
        
        //	密碼共16位，不足16位補F. ex.1234567890FFFFFF
        BYTE padding_pin[16] = {0};
        memset(padding_pin, 'F', sizeof(padding_pin));
        memcpy(padding_pin, card_pin, strlen(card_pin));
        
        //  Append password to APDU command buffer
        hex2bin((const char*)padding_pin, sizeof(padding_pin), &mSendBuffer[5]);
        
        mSendLength = 13;           //	指令傳送的資料長度( CLA=1, INS=1, P1=1, P2=1, Lc=8(PIN). Total=13 )
        mRecvLength = 256;          //	指令傳回的資料Max長度
        
#ifdef DEBUG
        char command[512] = {0};
        bin2hex(mSendBuffer, mSendLength, command);
        printf("=== command[%d] ===\n%s\n", mSendLength, command);
#endif
        
        return_code = SendAPDU(hCard, mSCardPCI,mSendBuffer, mSendLength, mRecvBuffer, &mRecvLength);
        
        *sw_code = GetSWCode(mRecvBuffer, &mRecvLength);
        
    }while(0);
    
    return return_code;
}

/**
 修改晶片卡密碼
 
 @param hCard 晶片卡的Handle (CannectCard取得)
 @param new_pin 晶片卡新密碼
 @param sw_code APDU SW錯誤代碼 (透過指標方式返回)
 @return 返回晶片卡錯誤代碼
 */
ULONG HTSmartCardUtility::ChangePIN(IN SCARDHANDLE      hCard,
                                    IN const char       *new_pin,
                                    OUT ULONG           *sw_code)
{
    ULONG return_code = SCARD_S_SUCCESS;
    *sw_code = SW_CODE_SUCCESS;
    
    do
    {
        /*
        return_code = this->SelectAID(hCard, sw_code);
        if (return_code != SCARD_S_SUCCESS || *sw_code != 0x9000){
            break;
        }
         */
        
        // Select EF 00C2
        BYTE EFID[] = { 0x00, 0xC2 };
        return_code = SelectEF(hCard, EFID, sw_code);
        if (return_code != SCARD_S_SUCCESS || *sw_code != 0x9000){
            break;
        }
        
        //  Clear buufer
        memset(mSendBuffer, 0, sizeof(mSendBuffer));
        memset(mRecvBuffer, 0, sizeof(mRecvBuffer));
        
        mSendBuffer[0] = 0x00;        //CLA    指令類別
        mSendBuffer[1] = 0xD2;        //INS    指令碼
        mSendBuffer[2] = 0x01;        //P1    參數
        mSendBuffer[3] = 0x04;        //P2    參數
        mSendBuffer[4] = 0x08;        //Lc    Data長度(單位:Byte)
        
        //    密碼共16位，不足16位補F. ex.1234567890FFFFFF
        BYTE padding_pin[16] = {0};
        memset(padding_pin, 'F', sizeof(padding_pin));
        memcpy(padding_pin, new_pin, strlen(new_pin));
        
        //  Append password to APDU command buffer
        hex2bin((const char*)padding_pin, sizeof(padding_pin), mSendBuffer+5);
        
        mSendLength = 13;           //    指令傳送的資料長度( CLA=1, INS=1, P1=1, P2=1, Lc=8(PIN). Total=13 )
        mRecvLength = 256;          //    指令傳回的資料Max長度
        
#ifdef DEBUG
        char command[512] = {0};
        bin2hex(mSendBuffer, mSendLength, command);
        printf("=== command[%d] ===\n%s\n", mSendLength, command);
#endif
        
        return_code = SendAPDU(hCard, mSCardPCI,mSendBuffer, mSendLength, mRecvBuffer, &mRecvLength);
        *sw_code = GetSWCode(mRecvBuffer, &mRecvLength);
        
    }while(0);
    
    return return_code;
}

/**
 讀取晶片卡發卡行代號

 @param hCard 晶片卡的Handle (CannectCard取得)
 @param IssuerID 晶片卡發卡行代號 (透過指標方式返回)
 @param sw_code APDU SW錯誤代碼 (透過指標方式返回)
 @return 返回晶片卡錯誤代碼
 */
ULONG HTSmartCardUtility::GetIssuerID(IN SCARDHANDLE      hCard,
                                      OUT char            *IssuerID,
                                      OUT ULONG           *sw_code)
{
    ULONG return_code = SCARD_S_SUCCESS;
    
    *sw_code = SW_CODE_SUCCESS;
    
    do
    {
        // Select EF 1001
        BYTE EFID[] = { 0x10,0x01 };
        return_code = SelectEF(hCard, EFID, sw_code);
        if (return_code != SCARD_S_SUCCESS || *sw_code != 0x9000){
            break;
        }
        
        //  Clear buufer
        memset(mSendBuffer, 0, sizeof(mSendBuffer));
        memset(mRecvBuffer, 0, sizeof(mRecvBuffer));
        
        *sw_code = SW_CODE_SUCCESS;
        
        //  發卡單位代號於 EF1001 中 RDID 01 (8 bytes, ANSI格式)
        
        BYTE record_data[11] = {0};
        return_code = ReadSigleRecord(hCard, 0x01, record_data, sw_code);
        if (return_code != SCARD_S_SUCCESS || *sw_code != 0x9000){
            break;
        }
        
        //  By pass RDID
        BYTE record_id = record_data[0];
        
        //  By pass Record Length
        BYTE record_len = record_data[1];
        
        printf("record_len =  %d", record_len);
        
        memcpy(IssuerID, record_data + 2, record_len);
        
    }while(0);
    
    return return_code;
}


/**
  讀取晶片卡主帳號

 @param hCard 晶片卡的Handle (CannectCard取得)
 @param account 晶片卡主帳號 (透過指標方式返回)
 @param sw_code APDU SW錯誤代碼 (透過指標方式返回)
 @return 返回晶片卡錯誤代碼
 */
ULONG HTSmartCardUtility::GetMainAccount(IN SCARDHANDLE hCard,
                                         OUT char       *account,
                                         OUT ULONG      *sw_code)
{
    ULONG return_code = SCARD_S_SUCCESS;
    
    *sw_code = SW_CODE_SUCCESS;
    
    do
    {
        // Select EF 1001
        BYTE EFID[] = { 0x10,0x01 };
        return_code = SelectEF(hCard, EFID, sw_code);
        if (return_code != SCARD_S_SUCCESS || *sw_code != 0x9000){
            break;
        }
        
        //  Clear buufer
        memset(mSendBuffer, 0, sizeof(mSendBuffer));
        memset(mRecvBuffer, 0, sizeof(mRecvBuffer));
        
        *sw_code = SW_CODE_SUCCESS;
        
        //  帳戶資料於 EF1001 中 RDID-03 ~ RDID-0A (16 bytes, ANSI格式)
        //  直接取第一筆帳號 RDID-03
        BYTE record_data[19] = {0};
        return_code = ReadSigleRecord(hCard, 0x03, record_data, sw_code);
        if (return_code != SCARD_S_SUCCESS || *sw_code != 0x9000){
            break;
        }

        //BYTE account_id = record_data[0];
        BYTE account_len = record_data[1];
        memcpy(account, &record_data[2], account_len);
        
        //  Trim Right
        while(account[account_len-1] == 0x20){
            account[--account_len] = '\0';
        }
        
    }while(0);
    
    return return_code;
}

/**
 讀取晶片卡所有帳號 (一卡多帳號)
 
 @param hCard 晶片卡的Handle (CannectCard取得)
 @param accounts 晶片卡中所有帳號 (透過指標方式返回)
 @param sw_code APDU SW錯誤代碼 (透過指標方式返回)
 @return 返回晶片卡錯誤代碼
 */
ULONG HTSmartCardUtility::GetAllAccount(IN SCARDHANDLE  hCard,
                                        OUT char        accounts[MAX_ACCOUNT][MAX_ACCOUNT_LEN],
                                        OUT ULONG       *sw_code)
{
    ULONG return_code = SCARD_S_SUCCESS;
    
    *sw_code = SW_CODE_SUCCESS;
    
    do
    {
        // Select EF 1001
        BYTE EFID[] = { 0x10,0x01 };
        return_code = SelectEF(hCard, EFID, sw_code);
        if (return_code != SCARD_S_SUCCESS || *sw_code != 0x9000){
            break;
        }
        
        //  Clear buufer
        memset(mSendBuffer, 0, sizeof(mSendBuffer));
        memset(mRecvBuffer, 0, sizeof(mRecvBuffer));
        
        *sw_code = SW_CODE_SUCCESS;
        
        BYTE record_data[256] = {0};
        
        //  帳戶資料於 EF1001 中 RDID-03 ~ RDID-0A (16 bytes, ANSI格式)
        return_code = ReadAllRecord(hCard, 0x03, record_data, sw_code);
        if (return_code != SCARD_S_SUCCESS || *sw_code != 0x9000){
            break;
        }
        
        char empty[] = {"0000000000000000"};
        
        BYTE *p = record_data;
        int i = 0;
        while(*p)
        {
            //  Get record id
            BYTE rdid = *(p++);
            
            //  Get record length
            BYTE account_len = *(p++);
            
            //  Get account
            char* account = (char*)p;
            p += account_len;
            
            //  Trim Right
            while(account[account_len-1] == 0x20){
                account[--account_len] = '\0';
            }
            
            //  check empty account
            if(strncmp(empty, account, account_len) != 0){
                memcpy(accounts[i++], account, account_len);
            }
        }
        
    }while(0);
    
    
    return return_code;
}


/**
 啟用二代Combo卡(信用卡+金融卡), 不執行此命令Combo卡驗密碼會失敗!!

 @param hCard 晶片卡的Handle (CannectCard取得)
 @param sw_code APDU SW錯誤代碼 (透過指標方式返回)
 @return 返回晶片卡錯誤代碼
 */
ULONG HTSmartCardUtility::SelectAID(IN SCARDHANDLE hCard, OUT ULONG  *sw_code)
{
    ULONG return_code = SCARD_S_SUCCESS;
    
    //  Clear buufer
    memset(mSendBuffer, 0, sizeof(mSendBuffer));
    memset(mRecvBuffer, 0, sizeof(mRecvBuffer));
    
    *sw_code = SW_CODE_SUCCESS;
    
    //	Select AID UPDA Command
    mSendBuffer[0] = 0x00; //   CLA	指令類別
    mSendBuffer[1] = 0xA4; //   INS	指令碼
    mSendBuffer[2] = 0x04; //   P1	參數
    mSendBuffer[3] = 0x00; //   P2	參數
    mSendBuffer[4] = 0x08;
    mSendBuffer[5] = 0xA0;
    mSendBuffer[6] = 0x00;
    mSendBuffer[7] = 0x00;
    mSendBuffer[8] = 0x01;
    mSendBuffer[9] = 0x72;
    mSendBuffer[10] = 0x95;
    mSendBuffer[11] = 0x00;
    mSendBuffer[12] = 0x01;
    mSendBuffer[13] = 0x00;
    
    mSendLength = 14;       //	指令傳送的資料長度
    mRecvLength = 256;      //	指令傳回的資料Max長度
    
#ifdef DEBUG
    char command[512] = {0};
    bin2hex(mSendBuffer, mSendLength, command);
    printf("=== %s command[%d] ===\n%s\n", __func__, mSendLength, command);
#endif
    
    return_code = SendAPDU(hCard, mSCardPCI, mSendBuffer, mSendLength, mRecvBuffer, &mRecvLength);
    
    *sw_code = GetSWCode(mRecvBuffer, &mRecvLength);
    
    return return_code;
    
}


/**
 選撢要讀取的EF檔

 @param hCard 晶片卡的Handle (CannectCard取得)
 @param EFID  要讀取得EF ID
 @param sw_code APDU SW錯誤代碼 (透過指標方式返回)
 @return 返回晶片卡錯誤代碼
 */
ULONG HTSmartCardUtility::SelectEF(IN   SCARDHANDLE         hCard,
                                   IN   BYTE                *EFID,
                                   OUT  ULONG               *sw_code)
{
    ULONG return_code = SCARD_S_SUCCESS;
    
    //  Clear buufer
    memset(mSendBuffer, 0, sizeof(mSendBuffer));
    memset(mRecvBuffer, 0, sizeof(mRecvBuffer));
    
    *sw_code = SW_CODE_SUCCESS;
    
    //	Select_EF
    mSendBuffer[0] = 0x00;	//CLA
    mSendBuffer[1] = 0xA4;	//INS
    mSendBuffer[2] = 0x02;	//P1
    mSendBuffer[3] = 0x00;	//P2
    mSendBuffer[4] = 0x02;	//Lc
    mSendBuffer[5] = EFID[0];
    mSendBuffer[6] = EFID[1];
    
    mSendLength = 7;
    mRecvLength = 256;
    
    return_code = SendAPDU(hCard, mSCardPCI, mSendBuffer, mSendLength, mRecvBuffer, &mRecvLength);
    
    *sw_code = GetSWCode(mRecvBuffer, &mRecvLength);
    
    return return_code;
    
}


/**
 讀取晶片卡中EF檔的單筆記錄資料

 @param hCard 晶片卡的Handle (CannectCard取得)
 @param record_id 欲讀取資料的 index
 @param record_data EF中指定的記錄資料(透過指標方式返回)
 @param sw_code APDU SW錯誤代碼 (透過指標方式返回)
 @return 返回晶片卡錯誤代碼
 */
ULONG HTSmartCardUtility::ReadSigleRecord(IN   SCARDHANDLE  hCard,
                                          IN   BYTE         record_id,
                                          OUT  BYTE         *record_data,
                                          OUT  ULONG        *sw_code)
{
    ULONG return_code = SCARD_S_SUCCESS;
    
    //  Clear buufer
    memset(mSendBuffer, 0, sizeof(mSendBuffer));
    memset(mRecvBuffer, 0, sizeof(mRecvBuffer));
    
    *sw_code = SW_CODE_SUCCESS;
    
    mSendBuffer[0] = 0x00;		//CLA
    mSendBuffer[1] = 0xB2;		//INS
    mSendBuffer[2] = record_id; //P1
    mSendBuffer[3] = 0x04;		//P2	04:讀取單筆資料	05讀取多筆資料
    mSendBuffer[4] = 0x00;		//Le
    
    mSendLength = 5;
    mRecvLength = 256;
    
#ifdef DEBUG
    char command[512] = {0};
    bin2hex(mSendBuffer, mSendLength, command);
    printf("=== %s command[%d] ===\n%s\n", __func__, mSendLength, command);
#endif
    
    return_code = SendAPDU(hCard, mSCardPCI, mSendBuffer, mSendLength, mRecvBuffer, &mRecvLength);
    *sw_code = GetSWCode(mRecvBuffer, &mRecvLength);
    if(return_code != SCARD_S_SUCCESS || *sw_code != 0x9000){
        return return_code;
    }
    
    memcpy(record_data, mRecvBuffer, mRecvLength);
    
    return return_code;
    
}


/**
  讀取晶片卡中EF檔的多筆記錄資料

 @param hCard 晶片卡的Handle (CannectCard取得)
 @param begin_id EF中第幾筆開始讀取
 @param RecordData EF中指定的多筆記錄資料(透過指標方式返回)
 @param sw_code APDU SW錯誤代碼 (透過指標方式返回)
 @return 返回晶片卡錯誤代碼
 */
ULONG HTSmartCardUtility::ReadAllRecord(IN   SCARDHANDLE  hCard,
                                        IN   BYTE         begin_id,
                                        OUT  BYTE         *RecordData,
                                        OUT  ULONG        *sw_code)
{
    ULONG return_code = SCARD_S_SUCCESS;
    
    //  Clear buufer
    memset(mSendBuffer, 0, sizeof(mSendBuffer));
    memset(mRecvBuffer, 0, sizeof(mRecvBuffer));
    
    *sw_code = SW_CODE_SUCCESS;
    
    mSendBuffer[0] = 0x00;		//CLA
    mSendBuffer[1] = 0xB2;		//INS
    mSendBuffer[2] = begin_id;  //P1
    mSendBuffer[3] = 0x05;		//P2	04:讀取單筆資料	05讀取多筆資料
    mSendBuffer[4] = 0x00;		//Le
    
    mSendLength = 5;
    mRecvLength = 256;
    
#ifdef DEBUG
    char command[512] = {0};
    bin2hex(mSendBuffer, mSendLength, command);
    printf("=== %s command[%d] ===\n%s\n", __func__, mSendLength, command);
#endif
    
    return_code = SendAPDU(hCard, mSCardPCI, mSendBuffer, mSendLength, mRecvBuffer, &mRecvLength);
    *sw_code = GetSWCode(mRecvBuffer, &mRecvLength);
    if(return_code != SCARD_S_SUCCESS || *sw_code != 0x9000){
        return return_code;
    }
    
    memcpy(RecordData, mRecvBuffer, mRecvLength);
    
    return return_code;
    
}


/**
 取讀卡片的帳戶基本資料

 @param hCard 晶片卡的Handle (CannectCard取得)
 @param profile 卡片帳戶結構化基本資料 (透過指標方式返回)
 @param sw_code APDU SW錯誤代碼 (透過指標方式返回)
 @return 返回晶片卡錯誤代碼
 */
ULONG HTSmartCardUtility::GetCardBaseProfile(IN  SCARDHANDLE     hCard,
                                             OUT CardBaseProfile *profile,
                                             OUT ULONG           *sw_code)
{
    ULONG return_code = SCARD_S_SUCCESS;
    *sw_code = SW_CODE_SUCCESS;
    
    do
    {
        // Select EF 1001
        BYTE EFID[] = { 0x10,0x01 };
        return_code = SelectEF(hCard, EFID, sw_code);
        if (return_code != SCARD_S_SUCCESS || *sw_code != 0x9000){
            break;
        }
        
        //  Clear buufer
        memset(mSendBuffer, 0, sizeof(mSendBuffer));
        memset(mRecvBuffer, 0, sizeof(mRecvBuffer));
        
        *sw_code = SW_CODE_SUCCESS;
        
        BYTE record_data[256] = {0};
        
        return_code = ReadAllRecord(hCard, 0x01, record_data, sw_code);
        if (return_code != SCARD_S_SUCCESS || *sw_code != 0x9000){
            break;
        }
        
        //  define Empty account,All of '0'
        char empty[] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00};
        
        BYTE *p = record_data;
        int i = 0;
        while(*p)
        {
            //  Get record id
            BYTE rdid = *(p++);
            
            //  Get record length
            BYTE record_len = *(p++);
            
            //  Get record data
            BYTE* record_data = p;
            p += record_len;
            
            //  Trim Right
            if (rdid != 0x02) {
                while(record_data[record_len-1] == 0x20){
                    record_data[--record_len] = '\0';
                }
            }
            
            //  Copy issuer code
            if (rdid == 0x01){
                memset(profile->IssuerNo, 0x00, sizeof(profile->IssuerNo));
                memcpy(profile->IssuerNo, record_data, record_len);
                profile->IssuerNoLen = record_len;
            }
            //  Copy remarks data
            else if (rdid == 0x02 && record_len != 0) {
                memset(profile->Remarks, 0x00, sizeof(profile->Remarks));
                profile->RemarksLen = bin2hex(record_data, record_len, profile->Remarks);
            }
            //  Copy Account data
            else {
                //  check empty account
                if(strncmp(empty, (char*)record_data, record_len) != 0)
                {
                    memset(profile->Accounts[i], 0x00, sizeof(profile->Accounts[i]));
                    profile->AccountsLen[i] = record_len;
                    memcpy(profile->Accounts[i++], record_data, record_len);
                    profile->AccountCount = i;
                }
            }
        }
        
    }while(0);
    
    return return_code;
}


/**
 寫入卡片記錄並壓製交易驗證碼(TAC)及交易序號(SNum)

 @param hCard 晶片卡的Handle (CannectCard取得)
 @param EFID 欲寫入卡片中的EF檔ID
 @param transData 欲寫入及壓製TAC的交易資料
 @param transDataLen 欲寫入及壓製TAC的交易資料長度
 @param SNum    交易序號 (透過指標方式返回)
 @param SNumLen 交易序號長度 (透過指標方式返回)
 @param TAC 交易驗證碼 (透過指標方式返回)
 @param TACLen 交易驗證碼長度 (透過指標方式返回)
 @param sw_code APDU SW錯誤代碼 (透過指標方式返回)
 @return 返回晶片卡錯誤代碼
 */
ULONG HTSmartCardUtility::WriteRecordWithSNUMTAC(IN   SCARDHANDLE   hCard,
                                                 IN   const BYTE    *EFID,
                                                 IN   const BYTE    *transData,
                                                 IN   BYTE          transDataLen,
                                                 OUT  BYTE          *SNum,
                                                 OUT  int           *SNumLen,
                                                 OUT  BYTE          *TAC,
                                                 OUT  int           *TACLen,
                                                 OUT  ULONG         *sw_code)
{
    ULONG return_code = SCARD_S_SUCCESS;
    
    //  Clear buufer
    memset(mSendBuffer, 0, sizeof(mSendBuffer));
    memset(mRecvBuffer, 0, sizeof(mRecvBuffer));
    mSendLength = 0;
    mRecvLength = 256;
    
    *sw_code = SW_CODE_SUCCESS;
    
    mSendBuffer[0] = 0x00;                              //  CLA
    mSendBuffer[1] = 0xE2;                              //  INS
    mSendBuffer[2] = EFID[0];                           //  P1
    mSendBuffer[3] = EFID[1];                           //  P2
    mSendBuffer[4] = transDataLen;                      //  Lc
    memcpy(&mSendBuffer[5], transData, transDataLen);   //  DATA
    mSendBuffer[5+transDataLen] = 0x00;                 //  Le
    
    mSendLength = 5 + transDataLen + 1;
    mRecvLength = 256;
    
#ifdef DEBUG
    char command[512] = {0};
    bin2hex(mSendBuffer, mSendLength, command);
    printf("=== %s command[%d] ===\n%s\n", __func__, mSendLength, command);
#endif
    
    return_code = SendAPDU(hCard, mSCardPCI, mSendBuffer, mSendLength, mRecvBuffer, &mRecvLength);
    *sw_code = GetSWCode(mRecvBuffer, &mRecvLength);
    if(return_code != SCARD_S_SUCCESS || *sw_code != 0x9000){
        return return_code;
    }
    
    //	Response ： SLen(1 Byte) + SNUM + 00(NULL) + TLen(1 Byte) + TAC Value + Status Code (2 Byte)
    
    BYTE *p = mRecvBuffer;
    
    *SNumLen = *(p++);          //  Get SNUM Length
    memcpy(SNum, p, *SNumLen);  //  Get SNUM Data
    
    p += *SNumLen + 1;
    
    *TACLen = *(p++);           //  Get TAC Length;
    memcpy(TAC, p, *TACLen);    //  Get TAC Data
    
    return return_code;
}

int HTSmartCardUtility::hex2bin(const char *hex, size_t hex_len, unsigned char *bin)
{
    char table[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    
    int i=0, j=0;
    
    for(i=0, j=0; i<hex_len; i+=2, j++)
    {
        BYTE bVal_16 = strchr(table, toupper(hex[i])) - table;
        BYTE bVal_0 = strchr(table, toupper(hex[i+1])) - table;
        
        bin[j]= bVal_16 * 16 + bVal_0;
    }
    return j;
}

int HTSmartCardUtility::bin2hex(const unsigned char* bin, size_t bin_len, char* hex)
{
    int i;
    for(i=0; i<(int)bin_len; i++){
        sprintf(hex + 2 * i, "%02X", bin[i]);
    }
    return i*2;
}

#pragma mark Inline Methods

static inline ULONG Initialize(SCARDCONTEXT *context)
{
    ULONG return_code = SCARD_S_SUCCESS;
    
    //  Establish the context.
    if (*context == SCARD_INVALID_HANDLE){
        return_code = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, context);
    }
    
    return return_code;
}

static inline ULONG Finalize(SCARDCONTEXT *context)
{
    ULONG return_code = SCARD_S_SUCCESS;
    
    //  Release the context.
    if (*context){
        return_code = SCardReleaseContext(*context);
        *context = SCARD_INVALID_HANDLE;
    }
    
    return return_code;
}

static inline ULONG SendAPDU(IN  SCARDHANDLE            hCard,
                             IN  SCARD_IO_REQUEST       *send_pci,
                             IN  const unsigned char    *send_buffer,
                             IN  unsigned int           send_length,
                             OUT unsigned char          *recv_buffer,
                             OUT unsigned int           *recv_length)
{
    
    ULONG return_code = SCardTransmit(hCard,        //  connected card handle
                                      send_pci,     //    smart card active SCARD_I0_REQUEST
                                      send_buffer,  //    send command
                                      send_length,  //    send command length
                                      NULL,         //    LPSCARD_IO_REQUEST (OUT)
                                      recv_buffer,  //    receive result (OUT)
                                      recv_length); //    receive length (OUT)
    
    return return_code;
}

static inline ULONG GetSWCode(IN OUT unsigned char *recv_buffer,
                              IN OUT unsigned int  *recv_length)
{
    ULONG sw_code = 0;
    if(*recv_length >= 2){
        //  get swtich code
        sw_code = (recv_buffer[*recv_length-2] << 8) | recv_buffer[*recv_length-1];
        
        //  clear switch code from buffer
        recv_buffer[--(*recv_length)] = 0;
        recv_buffer[--(*recv_length)] = 0;
    }
    return sw_code;
}
