#include "binIO.h"
#include "RippaSSL/error.h"
#include "RippaSSL/Base.h"
#include "RippaSSL/Mac.h"
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <vector>
#include <ios>
#include <iostream>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/params.h>

#define SEOS2_CMAC_LEN  16

int main(int argc, char* argv[])
{
    std::vector<uint8_t> iv;
    std::vector<uint8_t> key;
    RippaSSL::Algo     algo;
    int msgIdx;

    if (argc != 4)
    {
        printf("Usage: binmac MODE KEY MESSAGE\n"
               "    The key shall be provided without spaces. The same applies"
               " to the message and IV.\n"
               "    An example usage:\n"
               "    $ ./binmac AES128CBC 000102030405060708090A0B0C0D0E0F "
               "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D"
               "0E0F\n");
        printf("argc: %d\n", argc);
        return 1;
    }

    {
        char* myMode = argv[1];

        if (!strcmp(myMode, "AES128CBC"))
        {
            algo = RippaSSL::Algo::AES128CBC;
        }
        else if(!strcmp(myMode, "AES256CBC"))
        {
            algo = RippaSSL::Algo::AES256CBC;
        }
        else
        {
            printf("Check your MODE input!\nPossible values are:\n"
            "   AES128CBC, AES256CBC\n");
            return 1;
        }
    }


    BinIO::readHexBinary(key, argv[2]);
    if ((16 != key.size()) && (32 != key.size()))
    {
        printf("Wrong key length: %lu!\n", key.size());
        return 1;
    }

    // the message is the last argument:
    msgIdx = argc - 1;

    // reads the input message and places it into buf:
    std::vector<uint8_t> msgVector;
    BinIO::readHexBinary(msgVector, argv[msgIdx]);

    if (msgVector.size() < SEOS2_CMAC_LEN) {
        printf("Error! Your message is way too short. Please pad your data.\n");
        return 1;
    }

    std::vector<uint8_t> outputDigest;

    // optionally prints the input message:
    //for (size_t i = 0; i < msgVector.size(); ++i)
    //{
    //    std::cout << static_cast<int>(msgVector[i]) << " ";
    //}
    //std::cout << std::endl;

    // creates the relevant object:
    try {
        RippaSSL::Cmac myCmac {algo, RippaSSL::MacMode::CMAC, key, NULL};
        myCmac.finalize(outputDigest, msgVector);
    }
    catch (RippaSSL::InputError_NULLPTR& nullPtr) {
        printf("Error! The key pointer is invalid, or something nasty happened"
        " while calling OpenSSL's EVP_CIPHER_CTX_new()!\n");

        return 1;
    }
    catch (RippaSSL::OpenSSLError_CryptoInit& ci) {
        printf("Error! OpenSSL failed to call its Init method!\n");

        return 1;
    }
    catch (RippaSSL::OpenSSLError_CryptoUpdate& cu) {
        printf("Error! OpenSSL failed to call its Update method!\n");

        return 1;
    }
    catch (RippaSSL::OpenSSLError_CryptoFinalize& cf) {
        printf("Error: OpenSSL failed to call its Finalize method!\n");

        return 1;
    }

    // prints the result:
    outputDigest.resize(SEOS2_CMAC_LEN);
    printf("Result: ");
    BinIO::printHexBinary(outputDigest);

    return 0;
}

