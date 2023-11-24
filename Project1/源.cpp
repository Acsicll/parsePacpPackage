#include <stdio.h>  
#include <string.h>  
#pragma warning(disable:4996)
// 将一个四位十六进制数转换为十进制数  
int hexToDecimal(char hex[]) {
    int decimal = 0;
    int len = strlen(hex);
    for (int i = 0; i < len; i++) {
        int digit = hex[i];
        if (digit >= '0' && digit <= '9') {
            decimal += digit - '0';
        }
        else if (digit >= 'a' && digit <= 'f') {
            decimal += 10 + digit - 'a';
        }
        else if (digit >= 'A' && digit <= 'F') {
            decimal += 10 + digit - 'A';
        }
        decimal *= 16;
    }
    return decimal;
}

// 将一个十进制数转换为四位十六进制数，不足四位的在前面补零  
void decimalToHex(int decimal, char hex[]) {
    int len = sprintf(hex, "%04X", decimal);
    for (int i = len - 4; i < 4; i++) {
        hex[i] = '0';
    }
    hex[4] = '\0';
}

// 将两个四位十六进制数相加，处理进位，并输出结果  
void addHex(char hex1[], char hex2[], char result[]) {
    int decimal1 = hexToDecimal(hex1);
    int decimal2 = hexToDecimal(hex2);
    int decimal = decimal1 + decimal2;
    if (decimal >= 2048) { // 进位条件：大于等于2048（10000）  
        decimal += 1024; // 进位：加1024（8位二进制10000000）  
        result[0] = (decimal >> 12) + '0'; // 将最高位（百位）放入结果的最前面（最低位）  
        result[1] = (decimal >> 8) & 0xf + '0'; // 将次高位（十位）放入结果的次前面（倒数第二位）  
        result[2] = (decimal >> 4) & 0xf + '0'; // 将次低位（个位）放入结果的次后面（倒数第三位）  
        result[3] = decimal & 0xf + '0'; // 将最低位（十分位）放入结果的最后面（最高位）  
    }
    else { // 不进位  
        result[0] = decimal >> 12; // 将最高位（百位）放入结果的最前面（最低位）  
        result[1] = (decimal >> 8) & 0xf + '0'; // 将次高位（十位）放入结果的次前面（倒数第二位）  
        result[2] = (decimal >> 4) & 0xf + '0'; // 将次低位（个位）放入结果的次后面（倒数第三位）  
        result[3] = decimal & 0xf + '0'; // 将最低位（十分位）放入结果的最后面（最高位）  
    }
    result[4] = '\0'; // 结果为四位十六进制数，以字符串形式输出，需要在末尾添加字符串结束符'\0'  
}

int main() {
    char hex1[] = "0005"; // 要相加的第一个四位十六进制数，这里假设为a1b2（十六进制表示）  
    char hex2[] = "6d04"; // 要相加的第二个四位十六进制数，这里假设为c3d4（十六进制表示）  
    char result[5]; // 存储相加结果的变量，这里假设结果为a2b3（十六进制表示），因此长度为5足够用  
    addHex(hex1, hex2, result); // 调用addHex函数进行相加并处理进位，将结果存储到result变量中  
    printf("The result is: %s\n", result); // 输出结果，这里输出为a2b3（十六进制表示）  
    return 0; // 主函数结束，返回0表示程序正常结束  
}