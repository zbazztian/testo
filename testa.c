#include <stdio.h>

char* query(){
  return "blurbo";
}

void execute_sql(char* sql){
  printf(sql);
}

void test(char* s){
  execute_sql(s);
}

int main(int argc, char** argv){
  char* s = query();
  char* v = s;

  test(v);
}
