#include "stdafx.h"
#include "SHA512.h"
#include <fstream>
#include <iostream>
#include <string>

#define ROTR(n, x) ((x >> n) | (x << (64 - n)))
#define SHR(n, x) ((x >> n))
#define Ch(x, y, z) ((x & y) ^ ((!x) & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define S0(x) (ROTR(28, x) ^ ROTR(34, x) ^ ROTR(39, x))
#define S1(x) (ROTR(14, x) ^ ROTR(18, x) ^ ROTR(41, x))
#define s0(x) (ROTR(1, x) ^ ROTR(8, x) ^ SHR(7, x))
#define s1(x) (ROTR(19, x) ^ ROTR(61, x) ^ SHR(6, x))

int main(int argc, char *argv[])
{
    /*
        file operations
    */
    // get file name
    std::string fileName = "";

    if (argc == 1)
    {
        std::cout << "Filename: ";
        std::getline(std::cin, fileName);
    }
    else
        fileName = argv[1];

    // open file
    std::ifstream infile;
    infile.open(fileName);
    
    // get file length
    infile.seekg(0, infile.end);
    std::streamoff fileLength = infile.tellg();
    infile.seekg(0, infile.beg);

    if (fileLength < 0)
    {
        std::cout << "Unable to read file";
        return 1;
    }

    // read file contents into buffer
    unsigned int bufferLength = fileLength + 145 - ((fileLength + 17) % 128);
    char* buffer = new char[bufferLength];
    infile.read(buffer, fileLength);
    
    /*
        pre-processing
    */
    // append bit '1' to end of message
    buffer[fileLength] = 0x80;

    // pad with 0's
    size_t lengthSize = sizeof(fileLength);
    unsigned int padLength = 127 - ((fileLength + lengthSize) % 128);
    for (char i = 1; i <= padLength; i++)
        buffer[fileLength + i] = 0;

    // append message length
    for (char i = 1; i <= lengthSize; i++)
        buffer[fileLength + padLength + i] = fileLength >> ((lengthSize - i) * 8);

    // parse message into 64-bit words
    uint64_t* words = reinterpret_cast<uint64_t*>(buffer);
    const unsigned int numBlocks = bufferLength / 128;

    /*
        Hash computation
    */
    for (int N = 0; N < numBlocks; N++)
    {
        uint64_t* M = &words[N * 16];   // pointer to current block

        // 1. prepare the message schedule:
        uint64_t W[80];

        for (char t = 0; t < 16; t++)
            W[t] = M[t];

        for (char t = 16; t < 80; t++)
            W[t] = s1(W[t - 2]) + W[t - 7] + s0(W[t - 15]) + W[t - 16];

        // 2. initialize the 8 working variables:
        uint64_t a = H[0];
        uint64_t b = H[1];
        uint64_t c = H[2];
        uint64_t d = H[3];
        uint64_t e = H[4];
        uint64_t f = H[5];
        uint64_t g = H[6];
        uint64_t h = H[7];

        // 3. for t=0 to 79:
        uint64_t T1, T2;
        for (char t = 0; t < 80; t++)
        {
            T1 = h + S1(e) + Ch(e, f, g) + K[t] + W[t];
            T2 = S0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // 4. compute the intermediate hash values:
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    // print hash
    for (char i = 0; i < 8; i++)
        std::cout << '|' << std::hex << H[i];

    return 0;
}
