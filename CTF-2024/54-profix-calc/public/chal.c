#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#define MAX_EXPR_LEN 1024
#define MAX_STACK_HEIGHT 256

long long int stack[MAX_STACK_HEIGHT];
long long int *stack_top = stack;

void _abort(char const * err_msg) {
    printf("%s", err_msg);
    exit(1);
}

void push(long long int val) {
   *stack_top = val;
   stack_top++;
}

long long int pop() {
   stack_top--;
   return *stack_top;
}

int is_operator(char symbol) {
   return symbol == '+' || symbol == '-' || symbol == '*' || symbol == '/';
}

int is_dec_number(char symbol) {
   return symbol >= '0' && symbol <= '9';
}

int is_hex_number(char* expr) {
   return *expr == '0' && *(expr+1) == 'x';   
}

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  alarm(60);
}

long long int eval_expr(char* expression) {
   char *current = expression;
   long long int operand1, operand2;

   while (*current) {
      char symbol = *current;
      if (is_operator(symbol)) {
         operand2 = pop();
         operand1 = pop();
         switch(symbol) {
            case '+': push(operand1 + operand2); break;
            case '-': push(operand1 - operand2); break;
            case '*': push(operand1 * operand2); break;
            case '/': push(operand1 / operand2); break;
         }
         current++;
      }
      else if (isspace(symbol)) {
         current++;
      }
      else if (is_hex_number(current)) {
         push(strtoll(current, &current, 0));
      }
      else if (is_dec_number(symbol)) {
         push(strtoll(current, &current, 10));
      }
      else {
         _abort("invalid expression\n");
      }
   }
   
   return pop();
}

int main() {
   char expr[MAX_EXPR_LEN];
   init();

   printf("~Postfix expression calculator~\n");
   printf("expression(e.g. 9 6 - 11 *): ");
   int read_len = read(0, expr, MAX_EXPR_LEN-1);
   if (expr[read_len-1] == '\n')
      expr[read_len-1] = '\0';
   printf("Result: %lld\n", eval_expr(expr));
   return(0);
}