#include "stdio.h"
#include "stdlib.h"
#include "string.h"
int main(void){
    char str[24];
    read(0, str, 8);
    if(!strcmp(str, "test")){
        printf("test");
    }
    else if(!strcmp(str, "test2")){
        printf("test2");
    }
    else{
        printf("else");
    }
    return 0;
}