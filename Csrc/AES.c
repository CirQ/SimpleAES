/*************************************************************************
    > File Name: AES.c
    > Author: CirQ
    > Mail: CirQ999@163.com 
    > Created Time: 2016年10月24日 星期一 18时20分55秒
    # Description: to implement the AES encryptrion algorithm
    			   with key size 16 bytes
 ************************************************************************/
#define BLOCKSIZE 16
#define N 1
#define ROUND 10


#include<stdio.h>
#include"AES.h"


/*
 * used to buffer the block State
 * (means not the final cipher text)
 */
unsigned char stateBuffer[BLOCKSIZE];


/*
 * the key schedule for encryption
 * in 16 bytes key, it has 11 round keys
 */
unsigned char keySchedule[BLOCKSIZE *(ROUND+1)];


/*
 * define and save the general S box
 */
unsigned char S_box[256] = {
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
	0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
	0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
	0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
	0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
	0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
	0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
	0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
	0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
	0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
	0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
	0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
	0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
	0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
	0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
	0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
	0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};



/* 
 * to obtain the transpose of a 4-by-4 matrix
 *
 * input is a vector of length 16 (logically 4-by-4 matrix)
 */
void Transpose(unsigned char* m){
	for(int i = 0; i < 4; i++){
		for(int j = i; j < 4; j++){
			unsigned char tmp = m[4*i+j];
			m[4*i+j] = m[4*j+i];
			m[4*j+i] = tmp;
		}
	}
}
/*
 * to display a 16 bytes block
 */
void DisplayBlock(unsigned char* s){
	for(int i = 0; i < 4; i++){
		for(int j = 0; j < 4; j++)
			printf("%02X ", s[4*i+j]);
		putchar('\n');
	}
	putchar('\n');
}
/*
 * display the key schedule, 4 bytes in a group,
 * for a 16 bytes secret key, there are 11 round keys
 */
void ShowKeySchedule(){
	for(int i = 0; i < ROUND+1; i++){
		printf("round key %2d: ", i+1);
		
		Transpose(keySchedule + i*BLOCKSIZE);
		for(int j = 0; j < BLOCKSIZE; j++)
			printf("%02X", keySchedule[i*BLOCKSIZE + j]);
		Transpose(keySchedule + i*BLOCKSIZE);

		putchar('\n');
	}
}



/*
 * to transform a four byte tuple into
 * a single word
 *
 * input parameter is the address of a byte array,
 * and only the first four byte will be used
 */
unsigned int ByteToWord(unsigned char* fourByte){
	unsigned int re = 0;
	re += fourByte[0] * 256 * 256 * 256;
	re += fourByte[1] * 256 * 256;
	re += fourByte[2] * 256;
	re += fourByte[3];

	/* WHY IT IS WRONG?!
		re += ((unsigned int)fourByte[0]) << 24;
		re += ((unsigned int)fourByte[1]) << 16;
		re += ((unsigned int)fourByte[2]) << 8;
		re += ((unsigned int)fourByte[3]);
	*/

	return re;
}



/*
 * some intermediate function invoked
 * only in theKeyExpansion function
 * 
 * input parameter word is a word of secret key
 */
unsigned int SubRotWord(unsigned int word){
	unsigned char byte[4] = {0};
	for(int i = 3; i >= 0; i--){
		byte[i] = word % 256;
		word /= 256;
	}
	unsigned char tmp = byte[0];
	byte[0] = S_box[byte[1]];
	byte[1] = S_box[byte[2]];
	byte[2] = S_box[byte[3]];
	byte[3] = S_box[tmp];
	
	return ByteToWord(byte);
}
/*
 * used to expand the key
 * 
 * assume that the input parameter key is 16 bytes,
 * will generated 11 round keys in final
 */
void KeyExpansion(unsigned char* key){
	unsigned int RCon[10+1] = {
		0x0, 0x01, 0x02, 0x04, 0x08, 0x10,
			 0x20, 0x40, 0x80, 0x1B, 0x36
	};
	for(int i = 1; i <= 10; i++)
		RCon[i] = RCon[i] << 24;
	
	unsigned int word[4*(ROUND+1)] = {0};
	for(int i = 0; i < 4; i++)
		word[i] = ByteToWord(key + 4*i);

	for(int i = 4; i < 4*(ROUND+1); i++){
		unsigned int tmp = word[i-1];
		if(i % 4 == 0)
			tmp = SubRotWord(tmp) ^ RCon[i/4];
		word[i] = word[i-4] ^ tmp;
	}

	unsigned char* p = (unsigned char*)word;
	for(int i = 0; i < 4*4*(ROUND+1); i += 4){
		keySchedule[i+3] = *(p++);
		keySchedule[i+2] = *(p++);
		keySchedule[i+1] = *(p++);
		keySchedule[i] = *(p++);
	}
}



/*
 *
 */
void KeyExpansionReverse(unsigned char* key){}



/*
 * opeartion addRoundKey, used to
 * Xor the state with the round key
 *
 * parameter roundKey is a 16 bytes string (logically 4*4 block)
 * initially it is sorted by row, and is need to transposed so that
 * it is sorted by column
 */
void AddRoundKey(unsigned char* roundKey){
	Transpose(roundKey);
	for(int i = 0; i < BLOCKSIZE; i++)
		stateBuffer[i] = stateBuffer[i] ^ roundKey[i];
}



/*
 * using the S box, subsititude the bytes
 */
void SubBytes(){
	for(int i = 0; i < BLOCKSIZE; i++)
		stateBuffer[i] = S_box[stateBuffer[i]];
}



/*
 * shift the rows of the block, first row no shift,
 * next left shift 1 grid, next left shift 2 grids,
 * the last left shift 3 grids
 */
void ShiftRows(){
	unsigned char tmp[BLOCKSIZE];
	for(int i = 0; i < BLOCKSIZE; i++)
		tmp[i] = stateBuffer[i];

	stateBuffer[4] = tmp[5];
	stateBuffer[5] = tmp[6];
	stateBuffer[6] = tmp[7];
	stateBuffer[7] = tmp[4];

	stateBuffer[8] = tmp[10];
	stateBuffer[9] = tmp[11];
	stateBuffer[10] = tmp[8];
	stateBuffer[11] = tmp[9];

	stateBuffer[12] = tmp[15];
	stateBuffer[13] = tmp[12];
	stateBuffer[14] = tmp[13];
	stateBuffer[15] = tmp[14];
}



/*
 * perform multiplication a * b on
 * filed $F_{2^8}$
 */
unsigned char FieldMult(unsigned char a, unsigned char b){
	unsigned char re = 0;
	for(int i = 0; i < 8; i++){
		if(b & (unsigned char)1 != 0)
			re ^= a;
		unsigned char hi_bit_set = (unsigned char)(a & (unsigned char)(0x80));
		a <<= 1;
		if(hi_bit_set)
			a ^= 0x1B;  // $x^8 + x^4 + x^3 + x + 1
		b >>= 1;
	}
	return re;
}
/*
 * mix one four-dimension column in a block
 *
 * input is the address of that column
 */
void MixColumn(unsigned char* column){
	unsigned char t[4] = {0};
	for(int i = 0; i < 4; i++)
		t[i] = column[i];

	column[0] = FieldMult(t[0], 0x02) ^ FieldMult(t[1], 0x03) ^ t[2] ^ t[3];
	column[1] = FieldMult(t[1], 0x02) ^ FieldMult(t[2], 0x03) ^ t[3] ^ t[0];
	column[2] = FieldMult(t[2], 0x02) ^ FieldMult(t[3], 0x03) ^ t[0] ^ t[1];
	column[3] = FieldMult(t[3], 0x02) ^ FieldMult(t[0], 0x03) ^ t[1] ^ t[2];
}
/*
 * mixing four columns individually, since the input
 * are sorted by rows, it needs to be transposed
 */
void MixColumns(){
	Transpose(stateBuffer);
	MixColumn(stateBuffer);
	MixColumn(stateBuffer + 4);
	MixColumn(stateBuffer + 8);
	MixColumn(stateBuffer + 12);
	Transpose(stateBuffer);
}



/*
 * used to encrypt the plaintext
 * 
 * the input parameter is the plaintext and a 16 bytes key
 * the output is the ciphertext that as long as the plain
 */
void Encrypt(unsigned char* key, unsigned char* plaintext, unsigned char* ciphertext){
	int T = 0;  // T stands for term (of blocks)

	KeyExpansion(key);  // generate the key schedule

	while(T < N){
		for(int i = 0; i < BLOCKSIZE; i++)  // copy the block into buffer
			stateBuffer[i] = plaintext[T*BLOCKSIZE + i];
		Transpose(stateBuffer);
		
		AddRoundKey(keySchedule);

		for(int nr = 1; nr < ROUND; nr++){
			SubBytes(); ShiftRows(); MixColumns();
			AddRoundKey(keySchedule + nr*BLOCKSIZE);
		}

		SubBytes(); ShiftRows();
		AddRoundKey(keySchedule + ROUND*BLOCKSIZE);


		for(int i = 0; i < BLOCKSIZE; i++)
			ciphertext[T*BLOCKSIZE + i] = stateBuffer[i];
		Transpose(ciphertext + T*BLOCKSIZE);

		T++;
	}
}
/*
 *
 */
void Decrypt(unsigned char* key, unsigned char* ciphertext, unsigned char* plaintext){
	int T = 0;

	KeyExpansionReverse(key);

	while(T < N){



		T++;
	}
}



/*
 * input is a 16 bytes string
 */
void debug(unsigned char* s){
	for(int i = 0; i < BLOCKSIZE; i++)
		stateBuffer[i] = s[i];
	DisplayBlock(stateBuffer);
	Transpose(stateBuffer);
	DisplayBlock(stateBuffer);
	SubBytes();
	DisplayBlock(stateBuffer);
	ShiftRows();
	DisplayBlock(stateBuffer);
}


int main(){
	
	unsigned char key[16] = {
		0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
		0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
	};
	//debug(key);
	unsigned char plaintext[BLOCKSIZE * N] = {
		0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
		0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34
	};
	unsigned char ciphertext[BLOCKSIZE * N] = {0};

	printf("\nThe secret key is:\n");
	for(int i = 0; i < 16; i++)
		printf("%02X", key[i]);
	printf("\n\n");

	printf("\nThe plain-text is:\n");
	for(int i = 0; i < 16; i++)
		printf("%02X", plaintext[i]);
	printf("\n\n");

	Encrypt(key, plaintext, ciphertext);
	
	printf("\nThe key schedule is:\n");
	ShowKeySchedule();

	printf("\nThe cipher-text is:\n");
	for(int i = 0; i < 16; i++)
		printf("%02X", ciphertext[i]);
	printf("\n\n");
	

	return 0;
}
