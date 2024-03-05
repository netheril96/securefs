#pragma once

#include "lite_stream.h"
#include "tags.h"
#include "thread_local.h"

#include <fruit/fruit.h>

namespace securefs
{
namespace lite_format
{
    class StreamOpener
    {
    public:
        INJECT(StreamOpener(ANNOTATED(tContentMasterKey, key_type) content_master_key,
                            ANNOTATED(tPaddingMasterKey, key_type) padding_master_key,
                            ANNOTATED(tBlockSize, unsigned) block_size,
                            ANNOTATED(tIvSize, unsigned) iv_size,
                            ANNOTATED(tMaxPaddingSize, unsigned) max_padding_size,
                            ANNOTATED(tSkipVerification, bool) skip_verfication))
            : content_master_key_(content_master_key)
            , padding_master_key_(padding_master_key)
            , block_size_(block_size)
            , iv_size_(iv_size)
            , max_padding_size_(max_padding_size)
            , skip_verification_(skip_verfication)
        {
        }

        std::unique_ptr<securefs::lite::AESGCMCryptStream> open(std::shared_ptr<StreamBase> base);

    private:
        key_type content_master_key_, padding_master_key_;
        unsigned block_size_, iv_size_, max_padding_size_;
        bool skip_verification_;
        ThreadLocal content_ecb, padding_ecb;
    };
}    // namespace lite_format

}    // namespace securefs
