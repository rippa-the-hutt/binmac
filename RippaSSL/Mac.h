#ifndef RIPPASSL_MAC_H
#define RIPPASSL_MAC_H

#include "Base.h"

#include <openssl/evp.h>
#include <openssl/params.h>

#include <vector>
#include <map>

namespace RippaSSL {
    enum class MacMode
    {
        CMAC
    };

    class Cmac : public SymCryptoBase<CmacCtx, CmacHandle> {
        public:
            explicit Cmac(Algo                        algo,
                          MacMode                     mode,
                          const std::vector<uint8_t>& key,
                          const uint8_t*              iv,
                          bool                        padding = false);

            int update(      std::vector<uint8_t>& output,
                       const std::vector<uint8_t>& input);
            int finalize(      std::vector<uint8_t>& output,
                         const std::vector<uint8_t>& input);

            ~Cmac();

            // explicitly disables copy semantics:
            Cmac(const Cmac&)             = delete;
            Cmac& operator= (const Cmac&) = delete;

            // sports move semantics:
            Cmac(Cmac&& prev) : SymCryptoBase {std::move(prev)} {}
            Cmac& operator= (Cmac&&);

        private:
    };
}

#endif
