#include <cryptopp/scrypt.h>
#include <doctest/doctest.h>

#include "crypto.h"
#include "lite_fs.h"

#include <vector>

static void test_siv_encryption(const void* key,
                                size_t key_len,
                                const void* header,
                                size_t header_len,
                                const void* plaintext,
                                const void* ciphertext,
                                size_t text_len,
                                const void* siv)
{
    securefs::AES_SIV aes_siv(key, key_len);
    std::vector<byte> our_ciphertext(text_len);
    byte our_siv[16];
    aes_siv.encrypt_and_authenticate(
        plaintext, text_len, header, header_len, our_ciphertext.data(), our_siv);
    REQUIRE(memcmp(siv, our_siv, 16) == 0);
    REQUIRE(memcmp(ciphertext, our_ciphertext.data(), text_len) == 0);
}

static void test_siv_decryption(const void* key,
                                size_t key_len,
                                const void* header,
                                size_t header_len,
                                const void* plaintext,
                                const void* ciphertext,
                                size_t text_len,
                                const void* siv)
{
    securefs::AES_SIV aes_siv(key, key_len);
    std::vector<byte> our_plaintext(text_len);
    REQUIRE(aes_siv.decrypt_and_verify(
        ciphertext, text_len, header, header_len, our_plaintext.data(), siv));
    REQUIRE(memcmp(our_plaintext.data(), plaintext, text_len) == 0);
}

static void test_siv_all(const void* key,
                         size_t key_len,
                         const void* header,
                         size_t header_len,
                         const void* plaintext,
                         const void* ciphertext,
                         size_t text_len,
                         const void* siv)
{
    test_siv_encryption(key, key_len, header, header_len, plaintext, ciphertext, text_len, siv);
    test_siv_decryption(key, key_len, header, header_len, plaintext, ciphertext, text_len, siv);
}

TEST_CASE("Test SIV RFC")
{
    const byte key[] = {0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5,
                        0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
                        0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
    const byte ad[] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                       0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27};
    const byte plaintext[]
        = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    const byte siv[] = {0x85,
                        0x63,
                        0x2d,
                        0x7,
                        0xc6,
                        0xe8,
                        0xf3,
                        0x7f,
                        0x95,
                        0xa,
                        0xcd,
                        0x32,
                        0xa,
                        0x2e,
                        0xcc,
                        0x93};
    const byte ciphertext[]
        = {0x40, 0xc0, 0x2b, 0x96, 0x90, 0xc4, 0xdc, 0x4, 0xda, 0xef, 0x7f, 0x6a, 0xfe, 0x5c};

    test_siv_all(key, sizeof(key), ad, sizeof(ad), plaintext, ciphertext, sizeof(plaintext), siv);
}

TEST_CASE("Test SIV NIST")
{
    // The following AES-256 SIV tests come from:
    // http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/siv/siv-test-vectors.txt

    const byte siv1_key[64]
        = {0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3,
           0xf2, 0xf1, 0xf0, 0x6f, 0x6e, 0x6d, 0x6c, 0x6b, 0x6a, 0x69, 0x68, 0x67, 0x66,
           0x65, 0x64, 0x63, 0x62, 0x61, 0x60, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6,
           0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x01, 0x02, 0x03,
           0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    const byte siv1_h1[24]
        = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
           0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27};
    const byte siv1_plaintext[14]
        = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    const byte siv1_iv[16] = {0xf1,
                              0x25,
                              0x27,
                              0x4c,
                              0x59,
                              0x80,
                              0x65,
                              0xcf,
                              0xc2,
                              0x6b,
                              0x0e,
                              0x71,
                              0x57,
                              0x50,
                              0x29,
                              0x08};
    const byte siv1_ciphertext[14]
        = {0x8b, 0x03, 0x52, 0x17, 0xe3, 0x80, 0xca, 0xc8, 0x91, 0x9e, 0xe8, 0x00, 0xc1, 0x26};
    test_siv_all(siv1_key,
                 sizeof(siv1_key),
                 siv1_h1,
                 sizeof(siv1_h1),
                 siv1_plaintext,
                 siv1_ciphertext,
                 sizeof(siv1_plaintext),
                 siv1_iv);
}

TEST_CASE("Test CTR")
{
    const byte ciphertext[]
        = {0x22, 0x1d, 0xf9, 0x13, 0xf, 0xe, 0x5, 0xe7, 0xe8, 0x7c, 0x89, 0xee, 0x6a};
    const byte iv[] = {0x37,
                       0xc6,
                       0xd2,
                       0x2f,
                       0xad,
                       0xe2,
                       0x2b,
                       0x2d,
                       0x92,
                       0x45,
                       0x98,
                       0xbe,
                       0xe2,
                       0x45,
                       0x5e,
                       0xfc};
    const byte null_iv[16] = {0};
    const byte key[] = {0x7d,
                        0x9b,
                        0xb7,
                        0x22,
                        0xda,
                        0x2d,
                        0xc8,
                        0x67,
                        0x4e,
                        0x8,
                        0xc3,
                        0xd4,
                        0x4a,
                        0xae,
                        0x97,
                        0x6f};
    char plaintext[sizeof(ciphertext) + 1] = {0};

    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc(key, sizeof(key), null_iv);
    enc.Resynchronize(iv, sizeof(iv));
    enc.ProcessData(reinterpret_cast<byte*>(plaintext), ciphertext, sizeof(ciphertext));
    REQUIRE(strcmp(plaintext, "CTR Mode Test") == 0);
}

TEST_CASE("Test SIV other")
{
    const byte siv2_ciphertext[]
        = {0x7d, 0xf,  0x75, 0x43, 0xc7, 0xf2, 0x46, 0xb7, 0x61, 0x3f, 0x97, 0xad,
           0x91, 0x5d, 0x78, 0x98, 0xd1, 0x37, 0x68, 0xa2, 0xe7, 0xb,  0x22, 0xd8,
           0xd0, 0x1a, 0xa7, 0x1c, 0xe0, 0xa1, 0x20, 0x93, 0x3d, 0x4d, 0xc7, 0x8a,
           0x56, 0x19, 0x9,  0xa8, 0xed, 0x78, 0x87, 0xfd, 0x57, 0x29, 0xb2};
    const byte siv2_iv[] = {0x73,
                            0x74,
                            0xc6,
                            0x6c,
                            0xf5,
                            0xa8,
                            0x6a,
                            0x82,
                            0x4d,
                            0x27,
                            0x1a,
                            0x30,
                            0x9f,
                            0x77,
                            0xdf,
                            0x26};
    const byte siv2_key[64]
        = {0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x7a, 0x79, 0x78, 0x77, 0x76, 0x75, 0x74, 0x73,
           0x72, 0x71, 0x70, 0x6f, 0x6e, 0x6d, 0x6c, 0x6b, 0x6a, 0x69, 0x68, 0x67, 0x66,
           0x65, 0x64, 0x63, 0x62, 0x61, 0x60, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
           0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
           0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5b, 0x5d, 0x5e, 0x5f};
    const byte siv2_h1[40]
        = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
           0xee, 0xff, 0xde, 0xad, 0xda, 0xda, 0xde, 0xad, 0xda, 0xda, 0xff, 0xee, 0xdd, 0xcc,
           0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
    const byte siv2_plaintext[47]
        = {0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x73, 0x6f, 0x6d, 0x65,
           0x20, 0x70, 0x6c, 0x61, 0x69, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x20, 0x74,
           0x6f, 0x20, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x20, 0x75, 0x73,
           0x69, 0x6e, 0x67, 0x20, 0x53, 0x49, 0x56, 0x2d, 0x41, 0x45, 0x53};
    test_siv_all(siv2_key,
                 sizeof(siv2_key),
                 siv2_h1,
                 sizeof(siv2_h1),
                 siv2_plaintext,
                 siv2_ciphertext,
                 sizeof(siv2_plaintext),
                 siv2_iv);
}

TEST_CASE("Test filename enc/dec")
{
    const byte key[64]
        = {0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x7a, 0x79, 0x78, 0x77, 0x76, 0x75, 0x74, 0x73,
           0x72, 0x71, 0x70, 0x6f, 0x6e, 0x6d, 0x6c, 0x6b, 0x6a, 0x69, 0x68, 0x67, 0x66,
           0x65, 0x64, 0x63, 0x62, 0x61, 0x60, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
           0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
           0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5b, 0x5d, 0x5e, 0x5f};
    securefs::AES_SIV aes_siv(key, sizeof(key));
    const std::string path1 = "//cbdfsef/rsy/e\0xFF";
    std::string enc1 = securefs::lite::legacy_encrypt_path(aes_siv, path1);
    CAPTURE(enc1);
    REQUIRE(securefs::lite::legacy_decrypt_path(aes_siv, enc1) == path1);

    const std::string path2 = "../1239/uuuuu";
    std::string enc2 = securefs::lite::legacy_encrypt_path(aes_siv, path2);
    CAPTURE(enc2);
    REQUIRE(securefs::lite::legacy_decrypt_path(aes_siv, enc2) == path2);
}

TEST_CASE("Test hkdf")
{
    const byte key[] = {0x1d,
                        0x8e,
                        0x2a,
                        0xec,
                        0x9,
                        0xd3,
                        0x29,
                        0x1a,
                        0x15,
                        0xa5,
                        0x8,
                        0x78,
                        0x6a,
                        0x2f,
                        0xdc,
                        0x28};
    const byte salt[] = {0x0,
                         0x32,
                         0xb2,
                         0x36,
                         0x1,
                         0x41,
                         0x5b,
                         0x4f,
                         0x93,
                         0x96,
                         0xff,
                         0xde,
                         0x5e,
                         0xb7,
                         0xa5,
                         0x3c};
    const byte true_derived_key[]
        = {0x49, 0x68, 0xbe, 0xf9, 0x9c, 0x95, 0x12, 0x73, 0xd0, 0x76, 0x4d, 0x66, 0x71, 0x37, 0xb,
           0x6d, 0x76, 0xa8, 0xc9, 0xd7, 0xee, 0x7f, 0x64, 0xe3, 0xc0, 0xb7, 0x13, 0x4f, 0xff, 0xf9,
           0xa3, 0x15, 0x1c, 0x2c, 0x72, 0x86, 0x47, 0x72, 0xdb, 0xd2, 0xf3, 0x22, 0x7d, 0xd2, 0xb6,
           0x7d, 0x83, 0x33, 0xad, 0x64, 0xf2, 0xe7, 0xb9, 0xcd, 0x7b, 0x7,  0xa,  0x86, 0xa4, 0xa3,
           0x6d, 0x20, 0xa4, 0xc5, 0x43, 0x9d, 0x90, 0x0,  0xe5, 0xcd, 0x6,  0x53, 0x1d, 0xe5, 0xbb,
           0x1e, 0xe0, 0xdb, 0x65, 0x2d, 0x75, 0x21, 0xbe, 0x2e, 0xc9, 0xbd, 0x5a, 0x8f, 0xa2, 0xf7,
           0x5,  0x1d, 0x88, 0xc,  0x26, 0x3a, 0x71, 0x5,  0x2d, 0x2};
    byte test_derived[sizeof(true_derived_key)];
    const char* info = "hkdf-example";
    securefs::hkdf(key,
                   sizeof(key),
                   salt,
                   sizeof(salt),
                   info,
                   strlen(info),
                   test_derived,
                   sizeof(test_derived));
    REQUIRE(memcmp(test_derived, true_derived_key, sizeof(test_derived)) == 0);
}

static void test_scrypt(const char* password,
                        const char* salt,
                        uint64_t N,
                        uint32_t r,
                        uint32_t p,
                        size_t dkLen,
                        const char* expected)
{
    std::vector<byte> output(dkLen);
    CryptoPP::Scrypt scrypt;
    scrypt.DeriveKey(output.data(),
                     output.size(),
                     reinterpret_cast<const byte*>(password),
                     strlen(password),
                     reinterpret_cast<const byte*>(salt),
                     strlen(salt),
                     N,
                     r,
                     p);
    CAPTURE(password);
    CAPTURE(salt);
    CHECK(memcmp(expected, output.data(), dkLen) == 0);
}

TEST_CASE("scrypt")
{
    test_scrypt("",
                "",
                16,
                1,
                1,
                64,
                "\x77\xd6\x57\x62\x38\x65\x7b\x20\x3b\x19\xca\x42\xc1\x8a\x04"
                "\x97\xf1\x6b\x48\x44\xe3\x07\x4a\xe8\xdf\xdf\xfa\x3f\xed\xe2"
                "\x14\x42\xfc\xd0\x06\x9d\xed\x09\x48\xf8\x32\x6a\x75\x3a\x0f"
                "\xc8\x1f\x17\xe8\xd3\xe0\xfb\x2e\x0d\x36\x28\xcf\x35\xe2\x0c"
                "\x38\xd1\x89\x06");
    test_scrypt("password",
                "NaCl",
                1024,
                8,
                16,
                64,
                "\xfd\xba\xbe\x1c\x9d\x34\x72\x00\x78\x56\xe7"
                "\x19\x0d\x01\xe9\xfe\x7c\x6a\xd7\xcb\xc8\x23"
                "\x78\x30\xe7\x73\x76\x63\x4b\x37\x31\x62\x2e"
                "\xaf\x30\xd9\x2e\x22\xa3\x88\x6f\xf1\x09\x27"
                "\x9d\x98\x30\xda\xc7\x27\xaf\xb9\x4a\x83\xee"
                "\x6d\x83\x60\xcb\xdf\xa2\xcc\x06\x40");
    test_scrypt("pleaseletmein",
                "SodiumChloride",
                16384,
                8,
                1,
                64,
                "\x70\x23\xbd\xcb\x3a\xfd\x73\x48\x46"
                "\x1c\x06\xcd\x81\xfd\x38\xeb\xfd\xa8"
                "\xfb\xba\x90\x4f\x8e\x3e\xa9\xb5\x43"
                "\xf6\x54\x5d\xa1\xf2\xd5\x43\x29\x55"
                "\x61\x3f\x0f\xcf\x62\xd4\x97\x05\x24"
                "\x2a\x9a\xf9\xe6\x1e\x85\xdc\x0d\x65"
                "\x1e\x40\xdf\xcf\x01\x7b\x45\x57\x58"
                "\x87");

    /** This is too expensive
    test_scrypt("pleaseletmein", "SodiumChloride", 1048576, 8, 1, 64,
    "\x21\x01\xcb\x9b\x6a\x51\x1a\xae\xad\xdb\xbe\x09\xcf\x70\xf8\x81\xec\x56\x8d\x57\x4a\x2f\xfd\x4d\xab\xe5\xee\x98\x20\xad\xaa\x47\x8e\x56\xfd\x8f\x4b\xa5\xd0\x9f\xfa\x1c\x6d\x92\x7c\x40\xf4\xc3\x37\x30\x40\x49\xe8\xa9\x52\xfb\xcb\xf4\x5c\x6f\xa7\x7a\x41\xa4");
     **/
}
