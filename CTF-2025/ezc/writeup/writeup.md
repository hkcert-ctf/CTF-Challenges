# ezc

The key point of this challenge is pseudo-random number generation. Although srand is used, the parameter passed to it has a limited range. Therefore, we can write a C program in Linux that brute-forces srand values from 0 to 20, XORs all values, and checks which one is the flag.

```C
#include<stdio.h>
#include <stdlib.h>

int main(){
	unsigned char cipher[36] = {
		0x1F, 0xC9, 0xED, 0x29, 0xA6, 0xFE, 0x44, 0xEE, 0x82, 0x45, 0xE9, 0xD8, 0x7F, 0x42, 0x10, 0xE0,
		0xBB, 0x4B, 0xD0, 0x05, 0x4C, 0x76, 0x90, 0xCB, 0x48, 0x9C, 0x7A, 0xA9, 0xF0, 0x33, 0x55, 0x25,
		0x64, 0x88, 0x3D, 0xF7
	};
	for (int i=0;i<20;i++){
		srand(i);
		for (int j=0;j<36;j++){
			printf("%c", cipher[j]^rand());
		}
		printf("\n");
	}
	return 0;
}

```

