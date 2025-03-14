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
                    CryptReleaseContext(hprob, 0);
                    return 1;
                }
                if (fgets(buffer, size, stdin) != NULL) {
                    
                    buffer[strcspn(buffer, "\n")] = 0;
                    printf("You entered: %s\n", buffer);
                }
                else {
                    perror("Error reading input");
                    free(buffer);
                    CryptReleaseContext(hprob, 0);
                    return 1;
                }
                append_text_to_file(filename, buffer);
                free(buffer);
                CryptReleaseContext(hprob, 0);
                break;
            }
            case 2: {
                printf("Enter the password \n");
                size_t size = 128;
                char* buffer = malloc(size);
                if (buffer == NULL) {
                    perror("Unable to allocate buffer");
                    CryptReleaseContext(hprob, 0);
                    return 1;
                }

                if (fgets(buffer, size, stdin) != NULL) {
                    
                    buffer[strcspn(buffer, "\n")] = 0;
                    printf("You entered: %s\n", buffer);
                }
                else {
                    perror("Error reading input");
                    free(buffer);
                    CryptReleaseContext(hprob, 0);
                    return 1;
                }

                HCRYPTHASH yhash;
                if (!CryptCreateHash(hprob, CALG_MD5, 0, 0, &yhash)) {
                    printf("Error creating hash: %lu\n", GetLastError());
                    free(buffer);
                    CryptReleaseContext(hprob, 0);
                    return 1;
                }

                if (!CryptHashData(yhash, (BYTE*)buffer, strlen(buffer), 0)) {
                    printf("Error hashing data: %lu\n", GetLastError());
                    CryptDestroyHash(yhash);
                    free(buffer);
                    CryptReleaseContext(hprob, 0);
                    return 1;
                }



                HCRYPTKEY hkey;
                if (!CryptDeriveKey(hprob, CALG_RC4, yhash, 0, &hkey)) {
                    printf("Failed when creating key: %lu\n", GetLastError());
                    CryptDestroyHash(yhash);
                    free(buffer);
                    CryptReleaseContext(hprob, 0);
                    return 1;
                }

                printf("Encrypting moment \n");
                size_t aaaa = 0;
                char* buffer22 = read_file_content("data.txt");
                if (buffer22 == NULL) {
                    perror("Unable to allocate buffer");
                    CryptDestroyKey(hkey);
                    CryptDestroyHash(yhash);
                    free(buffer);
                    free(buffer22);
                    CryptReleaseContext(hprob, 0);
                    return 1;
                }

                printf("%s", buffer22);


                printf("\n");

                
                DWORD dataLen = strlen(buffer22) + 1; 
                BYTE* dataToEncrypt = (BYTE*)malloc(dataLen);
                memcpy(dataToEncrypt, buffer22, dataLen);

                
                if (!CryptEncrypt(hkey, 0, TRUE, 0, dataToEncrypt, &dataLen, dataLen)) {
                    printf("Error encrypting data: %lu\n", GetLastError());
                    free(dataToEncrypt);
                    CryptDestroyKey(hkey);
                    CryptDestroyHash(yhash);
                    free(buffer);
                    free(buffer22);
                    CryptReleaseContext(hprob, 0);
                    return 1;
                }

                printf("\n");

                writeToFile("data.txt", dataToEncrypt);
                
                printf("Encrypted data: ");
                for (DWORD i = 0; i < dataLen; i++) {
                    printf("%x ", dataToEncrypt[i]);
                }
                printf("\n");
                
                CryptDestroyKey(hkey);
                CryptDestroyHash(yhash);
                free(buffer);
                free(buffer22);
                free(dataToEncrypt);
                CryptReleaseContext(hprob, 0);
                break;
            }
            case 3: {
                printf("Enter the password \n");
                size_t size = 128;
                char* buffer = malloc(size);
                if (buffer == NULL) {
                    perror("Unable to allocate buffer");
                    CryptReleaseContext(hprob, 0);
                    return 1;
                }

                if (fgets(buffer, size, stdin) != NULL) {
                    
                    buffer[strcspn(buffer, "\n")] = 0;
                    printf("You entered: %s\n", buffer);
                }
                else {
                    perror("Error reading input");
                    free(buffer);
                    CryptReleaseContext(hprob, 0);
                    return 1;
                }

                HCRYPTHASH yhash;
                if (!CryptCreateHash(hprob, CALG_MD5, 0, 0, &yhash)) {
                    printf("Error creating hash: %lu\n", GetLastError());
                    free(buffer);
                    CryptReleaseContext(hprob, 0);
                    return 1;
                }

                if (!CryptHashData(yhash, (BYTE*)buffer, strlen(buffer), 0)) {
                    printf("Error hashing data: %lu\n", GetLastError());
                    CryptDestroyHash(yhash);
                    free(buffer);
                    CryptReleaseContext(hprob, 0);
                    return 1;
                }



                HCRYPTKEY hkey;
                if (!CryptDeriveKey(hprob, CALG_RC4, yhash, 0, &hkey)) {
                    printf("Failed when creating key: %lu\n", GetLastError());
                    CryptDestroyHash(yhash);
                    free(buffer);
                    CryptReleaseContext(hprob, 0);
                    return 1;
                }

                char* buffer66 = read_file_content("data.txt");
                if (buffer66 == NULL) {
                    perror("Unable to allocate buffer");
                    CryptDestroyKey(hkey);
                    CryptDestroyHash(yhash);
                    free(buffer);
                    free(buffer66);
                    CryptReleaseContext(hprob, 0);
                    return 1;
                }

                DWORD dataLen = strlen(buffer66) + 1; 
                
                if (!CryptDecrypt(hkey, 0, TRUE, 0, buffer66, &dataLen)) {
                    printf("Error decrypting data: %lu\n", GetLastError());
                    CryptDestroyKey(hkey);
                    CryptDestroyHash(yhash);
                    free(buffer);
                    free(buffer66);
                    CryptReleaseContext(hprob, 0);
                    return 1;
                }

                
                printf(" \n Decrypted data: %s\n", buffer66);

                writeToFile("data.txt", buffer66);

                
                CryptDestroyKey(hkey);
                CryptDestroyHash(yhash);
                free(buffer);
                free(buffer66);
                CryptReleaseContext(hprob, 0);
                break;
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
                    CryptReleaseContext(hprob, 0);
                    return 1;
                }

                if (fgets(buffer, size, stdin) != NULL) {
                    
                    buffer[strcspn(buffer, "\n")] = 0;
                    printf("You entered: %s\n", buffer);
                }
                else {
                    perror("Error reading input");
                    free(buffer);
                    CryptReleaseContext(hprob, 0);
                    return 1;
                }
                filename = buffer;
                free(buffer);
            }
        }
    }



    CryptReleaseContext(hprob, 0);
    return 0;
}


