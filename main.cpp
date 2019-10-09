#include "chacha20.hpp"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

typedef std::vector<uint8_t> Bytes;

uint8_t char_to_uint[256];
const char uint_to_char[10 + 26 + 1] = "0123456789abcdefghijklmnopqrstuvwxyz";

Bytes str_to_bytes(const char *src){
    return Bytes(src, src + strlen(src));
}

Bytes hex_to_raw(const Bytes &src){
    size_t n = src.size();
    assert(n % 2 == 0);
    Bytes dst(n/2);
    for (size_t i = 0; i < n/2; i++){
        uint8_t hi = char_to_uint[src[i*2 + 0]];
        uint8_t lo = char_to_uint[src[i*2 + 1]];
        dst[i] = (hi << 4) | lo;
    }
    return dst;
}

Bytes raw_to_hex(const Bytes &src){
    size_t n = src.size();
    Bytes dst(n*2);
    for (size_t i = 0; i < n; i++){
        uint8_t hi = (src[i] >> 4) & 0xf;
        uint8_t lo = (src[i] >> 0) & 0xf;
        dst[i*2 + 0] = uint_to_char[hi];
        dst[i*2 + 1] = uint_to_char[lo];
    }
    return dst;
}

bool operator == (const Bytes &a, const Bytes &b){
    size_t na = a.size();
    size_t nb = b.size();
    if (na != nb) return false;
    return memcmp(a.data(), b.data(), na) == 0;
}

void test_keystream(
    const char *text_key,
    const char *text_nonce,
    const char *text_keystream
){
    Bytes key       = hex_to_raw(str_to_bytes(text_key));
    Bytes nonce     = hex_to_raw(str_to_bytes(text_nonce));
    Bytes keystream = hex_to_raw(str_to_bytes(text_keystream));

    // Since Chacha20 just XORs the plaintext with the keystream,
    // we can feed it zeros and we will get the keystream.
    Bytes zeros(keystream.size(), 0);
    Bytes result(zeros);

    Chacha20 chacha(key.data(), nonce.data());
    chacha.crypt(&result[0], result.size());

    assert(result == keystream);
}

void test_crypt(
    const char *text_key,
    const char *text_nonce,
    const char *text_plain,
    const char *text_encrypted,
    uint64_t counter
){
    Bytes key       = hex_to_raw(str_to_bytes(text_key));
    Bytes nonce     = hex_to_raw(str_to_bytes(text_nonce));
    Bytes plain     = hex_to_raw(str_to_bytes(text_plain));
    Bytes encrypted = hex_to_raw(str_to_bytes(text_encrypted));

    Chacha20 chacha(key.data(), nonce.data(), counter);

    Bytes result(plain);
    // Encryption and decryption are the same operation.
    chacha.crypt(&result[0], result.size());

    assert(result == encrypted);
}

uint32_t adler32(const uint8_t *bytes, size_t n_bytes){
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < n_bytes; i++){
        a = (a + bytes[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

void test_encrypt_decrypt(uint32_t expected_adler32_checksum){
    // Encrypt and decrypt a megabyte of [0, 1, 2, ..., 255, 0, 1, ...].
    Bytes bytes(1024 * 1024);
    for (size_t i = 0; i < bytes.size(); i++) bytes[i] = i & 255;
    
    // Encrypt
    
    // Best password by consensus.
    uint8_t key[32] = {1, 2, 3, 4, 5, 6};
    // Really does not matter what this is, except that it is only used once.
    uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    Chacha20 chacha(key, nonce);
    chacha.crypt(bytes.data(), bytes.size());
    
    // Verify by checksum that the encrypted text is as expected.
    // Note that the adler32 checksum is not cryptographically secure.
    // It is only used for testing here.
    uint32_t checksum = adler32(bytes.data(), bytes.size());
    assert(checksum == expected_adler32_checksum);
    
    // Decrypt
    
    // Reset ChaCha20 de/encryption object.
    chacha = Chacha20(key, nonce);
    chacha.crypt(bytes.data(), bytes.size());
    
    // Check if crypt(crypt(input)) == input.
    for (size_t i = 0; i < bytes.size(); i++) assert(bytes[i] == (i & 255));
}

int main(){
    // Initialize lookup table
    for (int i = 0; i < 10; i++) char_to_uint[i + '0'] = i;
    for (int i = 0; i < 26; i++) char_to_uint[i + 'a'] = i + 10;
    for (int i = 0; i < 26; i++) char_to_uint[i + 'A'] = i + 10;

    // From rfc7539.txt
    test_crypt("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586", 0);
    test_crypt("0000000000000000000000000000000000000000000000000000000000000001", "0000000000000002", "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f", "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221", 1);
    test_crypt("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0", "0000000000000002", "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e", "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1", 42);
    test_keystream("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000", "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
    test_keystream("0000000000000000000000000000000000000000000000000000000000000001", "0000000000000000", "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963");
    test_keystream("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000001", "de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3");
    test_keystream("0000000000000000000000000000000000000000000000000000000000000000", "0100000000000000", "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b");
    test_keystream("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "0001020304050607", "f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9");
    
    test_encrypt_decrypt(3934073876);
    
    puts("Success! Tests passed.");

    return 0;
}
