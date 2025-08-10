#pragma once

#include "smart_handle.h"
#include "streams.h"

namespace securefs
{
class NTStream : public StreamBase
{
private:
    UniqueHandle m_handle;

public:
    explicit NTStream(UniqueHandle handle) : m_handle(std::move(handle)) {}

    length_type read(void* output, offset_type offset, length_type length) override;

    void write(const void* input, offset_type offset, length_type length) override;

    length_type size() const override;

    void flush() override;

    void resize(length_type) override;

    bool is_sparse() const noexcept override;
};
}    // namespace securefs
