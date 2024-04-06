#pragma once

#include <string>
#include <span>

#include <cryptopp/osrng.h>

using DERString = std::string;

// DER encode of the keys in ASN.1.
struct KeyPair
{
    DERString public_key;
    DERString private_key;

    std::string pemPublicKey() const;
    std::string pemPrivateKey() const;
};

std::string base64Encode(std::string_view data);
std::string base64Decode(std::string_view data);

class Crypto
{
public:
    KeyPair createKeyPair();
    std::string sig(const DERString& key, std::string_view msg);

private:
    CryptoPP::AutoSeededRandomPool random;
};
