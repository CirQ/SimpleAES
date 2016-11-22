/*************************************************************************
    > File Name: AES.h
    > Author: CirQ
    > Mail: CirQ999@163.com 
    > Created Time: 2016年10月25日 星期二 12时51分31秒
    # Description: the head file used to function declaration
 ************************************************************************/

void Transpose(unsigned char*);
void DisplayBlock(unsigned char*);
void ShowKeySchedule();

unsigned int ByteToWord(unsigned char*);

unsigned int SubRotWord(unsigned int);
void KeyExpansion(unsigned char*);

void KeyExpansionReverse(unsigned char*);

void AddRoundKey(unsigned char*);

void SubBytes();

void ShiftRows();

unsigned char FieldMult(unsigned char, unsigned char);
void MixColumn(unsigned char*);
void MixColumns();

void Encrypt(unsigned char*, unsigned char*, unsigned char*);
void Decrypt(unsigned char*, unsigned char*, unsigned char*);

void debug(unsigned char*);