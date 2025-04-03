#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wincrypt.h>


long get_file_size(const char* filename) {
    FILE* fp = fopen(filename, "rb");
    if (fp == NULL) {
        perror("Îøèáêà ïðè îòêðûòèè ôàéëà äëÿ îïðåäåëåíèÿ ðàçìåðà");
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    fclose(fp);
    return file_size;
}



#define SALT_SIZE 16;
#define ITERATIONS 1000;

char* read_file_content(const char* filename) {
    long file_size = get_file_size(filename);
    if (file_size == -1) {
        return NULL; 
    }

    FILE* fp = fopen(filename, "r");
    if (fp == NULL) {
        perror("Îøèáêà ïðè îòêðûòèè ôàéëà äëÿ ÷òåíèÿ");
        return NULL;
    }

    char* buffer = (char*)malloc(file_size + 1); 
    if (buffer == NULL) {
        fclose(fp);
        perror("Îøèáêà âûäåëåíèÿ ïàìÿòè äëÿ áóôåðà");
        return NULL;
    }

    size_t bytes_read = fread(buffer, 1, file_size, fp);
    if (bytes_read != (size_t)file_size) {
        fclose(fp);
        free(buffer);
        perror("Îøèáêà ïðè ÷òåíèè ôàéëà");
        return NULL;
    }

    buffer[file_size] = '\0'; 

    fclose(fp);
    return buffer;
}

BOOL append_text_to_file(const char* filename, const char* text) {
    FILE* fp = fopen(filename, "a"); 
    if (fp == NULL) {
        perror("Îøèáêà ïðè îòêðûòèè ôàéëà äëÿ äîáàâëåíèÿ");
        return FALSE;
    }

    size_t text_len = strlen(text);
    size_t bytes_written = fwrite(text, 1, text_len, fp);
    if (bytes_written != text_len) {
        fclose(fp);
        perror("Îøèáêà ïðè çàïèñè â ôàéë");
        return FALSE;
    }

    fclose(fp);
    return TRUE;
}




HCRYPTKEY PBKDF1(char* password, BYTE* salt, int c, HCRYPTPROV hprob, int u, HCRYPTHASH yhash) {


    HCRYPTKEY outputkey;
    if (u != 202) {
        if (!CryptGenRandom(hprob, 20, salt)) {
            fprintf(stderr, "CryptGenRandom failed: %x\n", GetLastError());
        }
    }



    DWORD passwordLen = strlen(password);
    /*HCRYPTHASH yhash;*/
    if (!CryptCreateHash(hprob, CALG_SHA1, 0, 0, &yhash)) {
        printf("Error creating hash: %lu\n", GetLastError());
    }
    BYTE* combined = (BYTE*)malloc(passwordLen + 20); 
    if (!combined) {
        fprintf(stderr, "Memory allocation failed\n");
        CryptDestroyHash(yhash);
        yhash = 0;
    }
    memcpy(combined, password, passwordLen);          
    memcpy(combined + passwordLen, salt, 20);          
    for (int i = 0; i < c; i++) {
        if (!CryptHashData(yhash, combined, passwordLen + 20, 0)) {
            printf("Error hashing data: %lu\n", GetLastError());
            free(combined);
            CryptDestroyHash(yhash);
            yhash = 0;
        }
    }
    if (!CryptDeriveKey(hprob, CALG_RC4, yhash, 0, &outputkey)) {
        printf("Failed when creating key: %lu\n", GetLastError());
        free(combined);
        CryptDestroyHash(yhash);
        yhash = 0;
    }
    if (combined) {
        free(combined);
        combined = NULL;
    }

    if (yhash && u!=202) {
        CryptDestroyHash(yhash);
        yhash = 0;
    }
    return outputkey;
}

void writeToFile(const char* filename, const BYTE * text) {
    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Îøèáêà îòêðûòèÿ ôàéëà äëÿ çàïèñè");
        return;
    }

    fprintf(file, "%s", text); 
    fclose(file);
}




int main() {
    HCRYPTPROV hprob;
    if (!CryptAcquireContext(&hprob, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        printf("Error when acquiring context: %lu\n", GetLastError());
        return 1;
    }
    char* filename = "data.txt";
    int o = 0;
    char* buffer = 0;
    char* buffer22 = 0;
    char* buffer66 = 0;
    BYTE* dataToEncrypt = 0;
    BYTE* salt = 0;
    int u = 0;


    HCRYPTHASH yhash = 0;
    HCRYPTKEY hkey = 0;
    while(o!=4){
        printf("1 for appending text to file \n 2 for ecnrypting text based on user input password \n 3 for decryption based on password (restart if you are ecnrypted before this session) \n 4 for exit \n 5 for chaning the filename (data.txt is base name) \n");
        scanf_s("%d", &o);
        getchar();
        switch (o) {
            case 1: {
                printf("Enter the appending text \n");
                size_t size = 128;
                char* buffer = malloc(size);
                if (buffer == NULL) {
                    perror("Unable to allocate buffer");
                    goto cleanup;
                }
                if (fgets(buffer, size, stdin) != NULL) {
                    
                    buffer[strcspn(buffer, "\n")] = 0;
                    printf("You entered: %s\n", buffer);
                }
                else {
                    perror("Error reading input");
                    goto cleanup;
                }
                append_text_to_file(filename, buffer);
                goto cleanup;
            }
            case 2: {
                printf("Enter the password \n");
                size_t size = 128;
                char* buffer = malloc(size);
                if (buffer == NULL) {
                    perror("Unable to allocate buffer");
                    goto cleanup;
                }

                if (fgets(buffer, size, stdin) != NULL) {
                    
                    buffer[strcspn(buffer, "\n")] = 0;
                    printf("You entered: %s\n", buffer);
                }
                else {
                    perror("Error reading input");
                    goto cleanup;
                }



                /*HCRYPTHASH yhash;*/
                if (!CryptCreateHash(hprob, CALG_MD5, 0, 0, &yhash)) {
                    printf("Error creating hash: %lu\n", GetLastError());
                    goto cleanup;
                }



                if (!CryptHashData(yhash, (BYTE*)buffer, strlen(buffer), 0)) {
                    printf("Error hashing data: %lu\n", GetLastError());
                    goto cleanup;
                }



                /*HCRYPTKEY hkey;*/
                if (!CryptDeriveKey(hprob, CALG_RC4, yhash, 0, &hkey)) {
                    printf("Failed when creating key: %lu\n", GetLastError());
                    goto cleanup;
                }

                printf("Encrypting moment \n");
                size_t aaaa = 0;
                char* buffer22 = read_file_content("data.txt");
                if (buffer22 == NULL) {
                    perror("Unable to allocate buffer");
                    goto cleanup;
                }

                printf("%s", buffer22);


                printf("\n");

                
                DWORD dataLen = strlen(buffer22) + 1; 
                BYTE* dataToEncrypt = (BYTE*)malloc(dataLen);
                memcpy(dataToEncrypt, buffer22, dataLen);

                
                if (!CryptEncrypt(hkey, 0, TRUE, 0, dataToEncrypt, &dataLen, dataLen)) {
                    printf("Error encrypting data: %lu\n", GetLastError());
                    goto cleanup;
                }
                
                printf("\n");

                writeToFile("data.txt", dataToEncrypt);
                
                printf("Encrypted data: ");
                for (DWORD i = 0; i < dataLen; i++) {
                    printf("%x ", dataToEncrypt[i]);
                }
                printf("\n");
                

                
                goto cleanup;
                break;
            }
            case 3: {
                printf("Enter the password \n");
                size_t size = 128;
                char* buffer = malloc(size);
                if (buffer == NULL) {
                    perror("Unable to allocate buffer");
                    goto cleanup;
                }

                if (fgets(buffer, size, stdin) != NULL) {
                    
                    buffer[strcspn(buffer, "\n")] = 0;
                    printf("You entered: %s\n", buffer);
                }
                else {
                    perror("Error reading input");
                    goto cleanup;
                }

                /*HCRYPTHASH yhash;*/
                if (!CryptCreateHash(hprob, CALG_MD5, 0, 0, &yhash)) {
                    printf("Error creating hash: %lu\n", GetLastError());
                    goto cleanup;
                }

                if (!CryptHashData(yhash, (BYTE*)buffer, strlen(buffer), 0)) {
                    printf("Error hashing data: %lu\n", GetLastError());
                    goto cleanup;
                }



                /*HCRYPTKEY hkey;*/
                if (!CryptDeriveKey(hprob, CALG_RC4, yhash, 0, &hkey)) {
                    printf("Failed when creating key: %lu\n", GetLastError());
                    goto cleanup;
                }

                char* buffer66 = read_file_content("data.txt");
                if (buffer66 == NULL) {
                    perror("Unable to allocate buffer");
                    goto cleanup;
                }

                DWORD dataLen = strlen(buffer66) + 1; 
                
                if (!CryptDecrypt(hkey, 0, TRUE, 0, buffer66, &dataLen)) {
                    printf("Error decrypting data: %lu\n", GetLastError());
                    goto cleanup;
                }

                
                printf(" \n Decrypted data: %s\n", buffer66);

                writeToFile("data.txt", buffer66);

                

                
                goto cleanup;
                
            }
            case 4: {
                o = 4;
                break;
            }
            case 5: {
                printf("Enter new filename \n");
                size_t size = 128;
                char* buffer = malloc(size);
                if (buffer == NULL) {
                    perror("Unable to allocate buffer");
                    goto cleanup;
                }

                if (fgets(buffer, size, stdin) != NULL) {
                    
                    buffer[strcspn(buffer, "\n")] = 0;
                    printf("You entered: %s\n", buffer);
                }
                else {
                    perror("Error reading input");
                    goto cleanup;
                }
                filename = buffer;
                goto cleanup;
            }
            case 6: {
                printf("Enter the password \n");
                size_t size = 128;
                char* buffer = malloc(size);
                if (buffer == NULL) {
                    perror("Unable to allocate buffer");
                    goto cleanup;
                }

                if (fgets(buffer, size, stdin) != NULL) {

                    buffer[strcspn(buffer, "\n")] = 0;
                    printf("You entered: %s\n", buffer);
                }
                else {
                    perror("Error reading input");
                    goto cleanup;
                }






                
                salt = (BYTE*)malloc(20);
                hkey = PBKDF1(buffer, salt, 10, hprob, u, yhash);
                append_text_to_file("salt.txt", salt);

                printf("Encrypting moment \n");
                size_t aaaa = 0;
                char* buffer22 = read_file_content("data.txt");
                if (buffer22 == NULL) {
                    perror("Unable to allocate buffer");
                    goto cleanup;
                }

                printf("%s", buffer22);


                printf("\n");


                DWORD dataLen = strlen(buffer22) + 1;
                BYTE* dataToEncrypt = (BYTE*)malloc(dataLen);
                memcpy(dataToEncrypt, buffer22, dataLen);


                if (!CryptEncrypt(hkey, 0, TRUE, 0, dataToEncrypt, &dataLen, dataLen)) {
                    printf("Error encrypting data: %lu\n", GetLastError());
                    goto cleanup;
                }

                printf("\n");

                writeToFile("data.txt", dataToEncrypt);

                printf("Encrypted data: ");
                for (DWORD i = 0; i < dataLen; i++) {
                    printf("%x ", dataToEncrypt[i]);
                }
                printf("\n");



                goto cleanup;
                break;
            }
            case 7: {
                printf("Enter the password \n");
                size_t size = 128;
                char* buffer = malloc(size);
                if (buffer == NULL) {
                    perror("Unable to allocate buffer");
                    goto cleanup;
                }

                if (fgets(buffer, size, stdin) != NULL) {

                    buffer[strcspn(buffer, "\n")] = 0;
                    printf("You entered: %s\n", buffer);
                }
                else {
                    perror("Error reading input");
                    goto cleanup;
                }






                int p = get_file_size("salt.txt");
                salt = malloc(p);
                salt = (BYTE*)read_file_content("salt.txt");
                u = 202;
                hkey = PBKDF1(buffer, salt, 10, hprob, u, yhash);

                printf("Encrypting moment \n");
                size_t aaaa = 0;
                char* buffer22 = read_file_content("data.txt");
                if (buffer22 == NULL) {
                    perror("Unable to allocate buffer");
                    goto cleanup;
                }

                printf("%s", buffer22);


                printf("\n");


                DWORD dataLen = strlen(buffer22) + 1;
                BYTE* dataToEncrypt = (BYTE*)malloc(dataLen);
                memcpy(dataToEncrypt, buffer22, dataLen);

                

                char* buffer66 = read_file_content("data.txt");
                if (buffer66 == NULL) {
                    perror("Unable to allocate buffer");
                    goto cleanup;
                }

                dataLen = strlen(buffer66) + 1;

                if (!CryptDecrypt(hkey, 0, TRUE, 0, buffer66, &dataLen)) {
                    printf("Error decrypting data: %lu\n", GetLastError());
                    goto cleanup;
                }


                printf(" \n Decrypted data: %s\n", buffer66);

                writeToFile("data.txt", buffer66);
            }



        }
        cleanup:
            if (buffer) {
                free(buffer);
                buffer = NULL;
            }
            if (buffer22) {
                free(buffer22);
                buffer22 = NULL;
            }
            if (buffer66) {
                free(buffer66);
                buffer66 = NULL;
            }
            if (dataToEncrypt) {
                free(dataToEncrypt);
                dataToEncrypt = NULL;
            }
            if (hkey) {
                CryptDestroyKey(hkey);
                hkey = 0;
            }
            if (yhash) {
                CryptDestroyHash(yhash);
                yhash = 0;
            }
            if (salt) {
                free(salt);
                salt = NULL;
            }
    }



    CryptReleaseContext(hprob, 0);
    return 0;
}


