#include <format>
#include <span>

#include <cryptopp/asn.h>
#include <cryptopp/base64.h>
#include <cryptopp/xed25519.h>
#include <cryptopp/filters.h>
#include <cryptopp/cryptlib.h>

#include "crypto.hpp"

DERString KeyPair::pemPublicKey() const
{
    std::string result;
    CryptoPP::StringSource src(public_key, true, new CryptoPP::Base64Encoder(
        new CryptoPP::StringSink(result)));
    return std::format("-----BEGIN PUBLIC KEY-----\n{}-----END PUBLIC KEY-----",
                       result);
}

std::string KeyPair::pemPrivateKey() const
{
    std::string result;
    CryptoPP::StringSource src(private_key, true, new CryptoPP::Base64Encoder(
        new CryptoPP::StringSink(result)));
    return std::format("-----BEGIN PRIVATE KEY-----\n{}-----END PRIVATE KEY-----",
                       result);
}

std::string base64Encode(std::string_view data)
{
    std::string result;
    CryptoPP::ArraySource src(reinterpret_cast<const unsigned char*>(data.data()), data.size(),
                              true, new CryptoPP::Base64Encoder(
                                  new CryptoPP::StringSink(result)));
    return result;
}

std::string base64Decode(std::string_view data)
{
    std::string result;
    CryptoPP::ArraySource src(reinterpret_cast<const unsigned char*>(data.data()), data.size(),
                              true, new CryptoPP::Base64Decoder(
                                  new CryptoPP::StringSink(result)));
    return result;
}

KeyPair Crypto::createKeyPair()
{
    CryptoPP::ed25519::Signer signer;
    signer.AccessPrivateKey().GenerateRandom(random);
    KeyPair result;
    {
        CryptoPP::ed25519::Verifier verifier(signer);
        const CryptoPP::ed25519PublicKey& pub_key =
            dynamic_cast<const CryptoPP::ed25519PublicKey&>(
                verifier.GetPublicKey());
        CryptoPP::StringSink sink(result.public_key);
        pub_key.DEREncode(sink);
    }
    {
        const CryptoPP::ed25519PrivateKey& priv_key =
            dynamic_cast<const CryptoPP::ed25519PrivateKey&>(
                signer.GetPrivateKey());
        CryptoPP::StringSink sink(result.private_key);
        priv_key.DEREncode(sink);
    }
    return result;
}

std::string Crypto::sig(const DERString& key, std::string_view msg)
{
    CryptoPP::ed25519::Signer signer;
    CryptoPP::StringSource src(key, true);
    dynamic_cast<CryptoPP::ed25519PrivateKey&>(signer.AccessPrivateKey())
        .BERDecode(src);

    std::string signature;
    // Determine maximum signature size
    size_t siglen = signer.MaxSignatureLength();
    signature.resize(siglen);

    // Sign, and trim signature to actual size
    siglen = signer.SignMessage(random, reinterpret_cast<const unsigned char*>(
        msg.data()), msg.size(), reinterpret_cast<unsigned char*>(
            signature.data()));
    signature.resize(siglen);
    return signature;
}
