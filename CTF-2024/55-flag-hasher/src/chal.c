#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define MAX_LIST_LENGHT 16
#define MAX_BUF_LENGHT 1024

void _abort(char const * err_msg) {
    printf("%s", err_msg);
    exit(1);
}

char* compute_hash256(char* inp) {
   char *digest = calloc(32, 1);

   SHA256_CTX ctx;
   SHA256_Init(&ctx);
   SHA256_Update(&ctx, inp, strlen(inp));
   SHA256_Final(digest, &ctx);
   
   return digest;
}

void menu() {
   printf("      _           ___  _____   __  \n");
   printf("     | |         |__ \\| ____| / /  \n");
   printf("  ___| |__   __ _   ) | |__  / /_  \n");
   printf(" / __| '_ \\ / _` | / /|___ \\| '_ \\ \n");
   printf(" \\__ \\ | | | (_| |/ /_ ___) | (_) |\n");
   printf(" |___/_| |_|\\__,_|____|____/ \\___/ \n");
   printf("                                   \n");
   printf("1 - Compute sha256\n");
   printf("2 - Read Hash record\n");
}

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  alarm(60);
}

int main() {
   char* hashlist[MAX_LIST_LENGHT];
   char buf[MAX_BUF_LENGHT];

   init();

   char* flag = getenv("flag");
   if (flag == NULL)
      _abort("can't find the flag!\n");
   hashlist[0] = compute_hash256(flag);

   flag = NULL;
   clearenv();
   for (int i = 1; i < MAX_LIST_LENGHT; i++)
      hashlist[i] = NULL;
   memset(buf, 0, sizeof(buf));

   while(1) {
      menu();
      unsigned int action = 0;
      scanf("%d", &action);
      if (action == 1) {
         int i;
         for (i = 0; i < MAX_LIST_LENGHT; i++) {
            if (hashlist[i] == NULL)
               break;
         }

         if (i == MAX_LIST_LENGHT) {
            printf("OUT-OF-MEMORY! Cannot store new hashes anymore!\n");
            continue;
         }

         printf("Text to be hashed (max: %dbytes): ", MAX_BUF_LENGHT-1);
         int read_len = read(0, buf, MAX_BUF_LENGHT-1);
         if (buf[read_len-1] == '\n')
            buf[read_len-1] = '\0';
         hashlist[i] = compute_hash256(buf);
         memset(buf, 0, sizeof(buf));

         printf("Hash - %d : ", i);
         for(int j = 0; j < 32; j++) printf("%02hhX", hashlist[i][j]);
         printf("\n");
      } else if (action == 2) {
         unsigned int idx = 0;
         printf("Idx: ");
         scanf("%u", &idx);

         if (hashlist[idx] == NULL)
            _abort("Entry does not exist.\n");

         printf("Hash - %d : ", idx);
         for(int j = 0; j < 32; j++) printf("%02hhX", hashlist[idx][j]);
         printf("\n");
      } else {
         _abort("Unknown command.\n");
      }
   }

   return(0);
}