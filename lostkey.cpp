#include <eosiolib/crypto.h>
#include <eosiolib/eosio.hpp>

#define USE_KECCAK
#include "sha3/sha3.c"
#define uECC_SUPPORTS_secp160r1 0
#define uECC_SUPPORTS_secp192r1 0
#define uECC_SUPPORTS_secp224r1 0
#define uECC_SUPPORTS_secp256r1 0
#define uECC_SUPPORTS_secp256k1 1
#define uECC_SUPPORT_COMPRESSED_POINT 1
#include "ecc/uECC.c"

using namespace eosio;

class lostkey : public contract {
    public:
        using contract::contract;

    [[ eosio::action ]]
    void regethkey(std::vector<char> sig, name account, public_key newpubkey) {
        // ETH signatures sign the keccak256 hash of a message so we have to do the same
        sha3_ctx shactx;
        capi_checksum256 msghash;
        unsigned char message[26] = "I lost my EOS genesis key";
        rhash_keccak_256_init(&shactx);
        rhash_keccak_update(&shactx, message, 25); // ignore the null terminator at the end of the string
        rhash_keccak_final(&shactx, msghash.hash);

        // Recover the compressed ETH public key from the message and signature
        uint8_t compressed_pubkey[34];
        uint8_t pubkey[64];
        auto res = recover_key( 
            &msghash, 
            sig.data(),
            sig.size(),
            (char*)compressed_pubkey,
            34
        );
        eosio_assert(res == 34, "Recover key failed");

        // Decompress the ETH pubkey
        uECC_decompress(compressed_pubkey+1, pubkey, uECC_secp256k1());

        // Calculate the hash of the pubkey
        capi_checksum256 pubkeyhash;
        rhash_keccak_256_init(&shactx);
        rhash_keccak_update(&shactx, pubkey, 64);
        rhash_keccak_final(&shactx, pubkeyhash.hash);

        // last 20 bytes of the hashed pubkey = ETH address
        uint8_t eth_address[20];
        memcpy(eth_address, pubkeyhash.hash + 12, 20);

        // convert to human readable form
        std::string ethAddressStr = "0x" + bytetohex(eth_address, 20);
        
        // log human readable summary for easy retrieval
        action(permission_level{ _self, "active"_n },
            _self, "logethadd"_n,
            std::make_tuple(ethAddressStr, account, newpubkey)
        ).send();
    }

    [[ eosio::action ]]
    void logethadd(std::string ethaddress, name account, public_key newpubkey) {
        require_auth(_self);
    }

    private:

    std::string bytetohex(unsigned char *data, int len)
    {
        constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                   '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

        std::string s(len * 2, ' ');
        for (int i = 0; i < len; ++i) {
            s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
            s[2 * i + 1] = hexmap[data[i] & 0x0F];
        }
        return s;
    }
};

EOSIO_DISPATCH(lostkey, (regethkey)(logethadd))
