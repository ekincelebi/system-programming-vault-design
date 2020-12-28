/*
Students:   Farid Huseynov 150160904
            Gizem Ece
            Ekin Çelebi

    System Programming course
            Project II

            04.01.2021
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

char* get_permutation_function(char keytemp[], int key_length){
    char key[key_length];  // should be redeclared, otherwise throws seg. fault
    strcpy(key, keytemp);  // redefine

    char *p_function = malloc (sizeof (char) * 100);
    char min = 'z';
    int min_index;
    char smin_index[2];

    
    for(int i=0; i<key_length; i++){
        for(int j=0; j<key_length; j++){
            char temp = key[j];

            if(temp < min){
                min = temp;
                min_index = j;
            }
        }
        
        key[min_index] = 'z';  //done with ith element
        min = 'z';
        sprintf(smin_index, "%d", min_index+1);
        strcat(p_function, smin_index); 
    }
    return p_function;
}

char* apply_on_text(char tempText[], int text_length, char tempKey[], int key_length){
    char text[text_length];  // should be redeclared, otherwise throws seg. fault
    strcpy(text, tempText);  // redefine
    
    char key[key_length];  // should be redeclared, otherwise throws seg. fault
    strcpy(key, tempKey);  // redefine
    
    char *substr = malloc (sizeof (char) * key_length);
    char *decryptedText = malloc (sizeof (char) * text_length);
    strcpy(decryptedText, text);
    
    int loop_ctr = text_length / key_length;
    if(text_length % key_length != 0) loop_ctr++;

    for(int i=0; i<loop_ctr; i++){
        strncpy(substr, text+(i*key_length),key_length);
        for(int j=0; j<key_length; j++){
            decryptedText[j+i*key_length] = substr[key[j]-'0'-1];
        }
    }
    return decryptedText;
}

int main(){
    char myKey[10];
    char myText[100];

    fgets(myKey, 10, stdin);
    int lenKey=strlen(myKey); 
    if(myKey[lenKey-1]=='\n'){
        myKey[lenKey-1]='\0';
        lenKey--;
    }
    fgets(myText, 100, stdin);
    int lenText=strlen(myText); 
    if(myText[lenText-1]=='\n'){
        myText[lenText-1]='\0';
        lenText--;
    }
    char* p_function = get_permutation_function(myKey, lenKey);
    char* decryptedText = apply_on_text(myText, lenText, p_function, lenKey);
    printf("Decrypted: %s\n", decryptedText);
    return 0;
}