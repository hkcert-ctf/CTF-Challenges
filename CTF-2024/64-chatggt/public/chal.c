#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define QUESTION_BUF_SIZE 0x100

void get_shell() {
    system("/bin/sh");
}

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  alarm(60);
}

void start_chat() {
  char question[QUESTION_BUF_SIZE];

  while (1){
    printf("\nQuestion (Input EXIT to leave the chat): ");
    read(0, question, 300);
    if (strncmp(question, "EXIT", 4) == 0) break;
    printf("I don't understand \"%s\"?\n", question);
  }
}

int main() {
  init();
  printf(">>>ChatGGT 1.0<<<\n");
  start_chat();
  return(0);
}