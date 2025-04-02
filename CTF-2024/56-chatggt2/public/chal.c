#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define QUESTION_BUF_SIZE 0x100

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  alarm(60);
}

void start_chat() {
  char question[QUESTION_BUF_SIZE];
  char* answers[] = {
    "I'm not sure. Could you clarify?",
    "I don't know. Can you provide details?",
    "That's unclear. More information needed.",
    "I'm uncertain. What specifically do you mean?",
    "Not sure. Can you rephrase that?",
    "I don't have enough info to answer.",
    "Could you be more specific?",
    "I'm afraid I don't know that.",
    "Can you elaborate on your question?",
    "That's beyond my current knowledge.",
    "I'm not familiar with that topic.",
    "I'd need to research to answer that.",
    "Can you break down your question?",
    "I'm not confident about the answer.",
    "What exactly are you trying to understand?",
    "I'm not sure about that.",
    "Could you clarify, please?",
    "I don't know that one.",
    "Can you provide more details?",
    "I'm uncertain. Please explain further.",
    "That's beyond my knowledge.",
    "I need more information, please.",
    "Could you rephrase that?",
    "I'm not familiar with this.",
    "Can you be more specific?",
    "I'd have to research that.",
    "That's unclear to me.",
    "I can't answer with certainty.",
    "Please elaborate on your question.",
    "I'm afraid I don't know.",
    "You guess?",
    "Probably not.",
    "Hmmm... maybe.",
    "I don't think so.",
    "Yes.",
    "Nope."
  };
  int answer_idx = 0;

  while (1){
    printf("\nQuestion (Input EXIT to leave the chat): ");
    read(0, question, sizeof(question));
    if (strncmp(question, "EXIT", 4) == 0) break;
    printf(answers[answer_idx]);
    answer_idx = (answer_idx + 1) % sizeof(answers);
  }
}

int main() {
  init();
  printf(">>>ChatGGT 1.1<<<\n");
  start_chat();
  return(0);
}