#include <stdio.h>
#include <stdbool.h>

bool verifyFlag(const char *input) {
    if (input[0] != 'P')          return false;
    else if (input[1] != 'C')     return false;
    else if (input[2] != 'C')     return false;
    else if (input[3] != 'S')     return false;
    else if (input[4] != 'Y')     return false;
    else if (input[5] != 'K')     return false;
    else if (input[6] != '{')     return false;
    else if (input[7] != '5')     return false;
    else if (input[8] != 'h')     return false;
    else if (input[9] != '4')     return false;
    else if (input[10] != 'r')    return false;
    else if (input[11] != '3')    return false;
    else if (input[12] != '_')    return false;
    else if (input[13] != 'y')    return false;
    else if (input[14] != '0')    return false;
    else if (input[15] != 'u')    return false;
    else if (input[16] != 'r')    return false;
    else if (input[17] != '_')    return false;
    else if (input[18] != 'k')    return false;
    else if (input[19] != 'n')    return false;
    else if (input[20] != '0')    return false;
    else if (input[21] != 'w')    return false;
    else if (input[22] != 'l')    return false;
    else if (input[23] != '3')    return false;
    else if (input[24] != 'd')    return false;
    else if (input[25] != 'g')    return false;
    else if (input[26] != '3')    return false;
    else if (input[27] != '!')    return false;
    else if (input[28] != '}')    return false;
    else                         return true;
}

int main() {
    char input[50];

    printf("Masukkan flag: ");
    scanf("%49s", input);

    if (verifyFlag(input)) {
        printf("Flag benar!\n");
        return 0;
    } else {
        printf("Flag salah!\n");
        return false;
    }
}