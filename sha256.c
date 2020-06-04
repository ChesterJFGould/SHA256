#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <string.h>

#define BYTES_PER_BLOCK 64
#define INTS_PER_BLOCK 16
#define INTS_PER_HASH 8

unsigned int
uintRotateRight(unsigned int n, unsigned int amount)
{
	return (n >> amount) | (n << (32 - amount));
}

int
main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("Please give text to be hashed");

		return EXIT_FAILURE;
	}

	unsigned long long plaintextSize = strlen(argv[1]);

	int blockCount = (int)ceil(((float)plaintextSize + 1.0f + 8.0f) / (float)BYTES_PER_BLOCK);

	unsigned char paddedPlaintext[blockCount * BYTES_PER_BLOCK];

	memcpy(paddedPlaintext, argv[1], plaintextSize);


	// Append single 1 bit
	paddedPlaintext[plaintextSize] = 0x80;	

	// Append 0s
	for (int i = 0; i < ((blockCount * BYTES_PER_BLOCK) - (int)plaintextSize - 8 - 1); i++) {
		paddedPlaintext[plaintextSize + 1 + i] = 0;
	}

	// Append length of plaintext as 64 bit int
	
	for (int i = sizeof(unsigned long long); i > 0; i--) {
		paddedPlaintext[sizeof(paddedPlaintext) - i] = ((plaintextSize * 8) & (0xff << ((i - 1) * 8))) >> ((i - 1) * 8);	
	}

	// Split plaintext into 512 bit chunks
	unsigned char blocks[blockCount][BYTES_PER_BLOCK];

	// Copy paddedPlaintext into blocks
	memcpy(blocks, paddedPlaintext, sizeof(paddedPlaintext));
	
	// Hash values
	unsigned int h[INTS_PER_HASH] = {
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19
	};

	// Round constants
	const unsigned int k[] = {
		   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	for (int i = 0; i < blockCount; i++) {
		// Message schedule array
		unsigned int w[64];
		
		// Copy block into message schedule array
		// x86 ints are stored little endian while paddedPlaintext is stored big endian
		// so we write every 4 bytes reversed
		for (int j = 0; j < INTS_PER_BLOCK; j++) {
			w[j] = ((unsigned int)blocks[i][j * 4] << 24) | ((unsigned int)blocks[i][j * 4 + 1] << 16)
				| ((unsigned int)blocks[i][j * 4 + 2] << 8) | ((unsigned int)blocks[i][j * 4 + 3]);
		}



		// Fill the rest of message schedule array
		for (int j = 16; j < 64; j++) {
			unsigned int s0 = uintRotateRight(w[j - 15], 7) ^ uintRotateRight(w[j - 15], 18) ^ (w[j - 15] >> 3);
			unsigned int s1 = uintRotateRight(w[j - 2], 17) ^ uintRotateRight(w[j - 2], 19) ^ (w[j - 2] >> 10);
			w[j] = w[j - 16] + s0 + w[j - 7] + s1;
		}
	
		// Working variables, gets mixed with hash values at end
		unsigned int wh[INTS_PER_HASH];
		
		// Copy current hash values into working hash values
		memcpy(wh, h, sizeof(unsigned int) * INTS_PER_HASH);
		
		// Main hash loop
		for (int j = 0; j < 64; j++) {
			unsigned int S1 = uintRotateRight(wh[4], 6) ^ uintRotateRight(wh[4], 11) ^ uintRotateRight(wh[4], 25);
			unsigned int ch = (wh[4] & wh[5]) ^ ((~wh[4]) & wh[6]);
			unsigned int temp1 = wh[7] + S1 + ch + k[j] + w[j];
			unsigned int S0 = uintRotateRight(wh[0], 2) ^ uintRotateRight(wh[0], 13) ^ uintRotateRight(wh[0], 22);
			unsigned int maj = (wh[0] & wh[1]) ^ (wh[0] & wh[2]) ^ (wh[1] & wh[2]);
			unsigned int temp2 = S0 +maj;

			wh[7] = wh[6];
			wh[6] = wh[5];
			wh[5] = wh[4];
			wh[4] = wh[3] + temp1;
			wh[3] = wh[2];
			wh[2] = wh[1];
			wh[1] = wh[0];
			wh[0] = temp1 + temp2;
		}

		for (int j = 0; j < INTS_PER_HASH; j++) {
			h[j] += wh[j];
		}
	}

	for (int i = 0; i < INTS_PER_HASH; i++) {
		printf("%08x", h[i]);
	}

	printf("\n");

	return 0;
}
