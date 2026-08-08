#ifndef REALITY_VISION_BYTE_READER_HPP
#define REALITY_VISION_BYTE_READER_HPP

#include "byte_order.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace rv::core
{

class byte_reader
{
   public:
    explicit byte_reader(std::span<const std::uint8_t> input) noexcept : input_(input) {}

    [[nodiscard]] bool empty() const noexcept { return remaining() == 0; }
    [[nodiscard]] std::size_t remaining() const noexcept { return input_.size() - position_; }

    [[nodiscard]] bool read_u8(std::uint8_t& value) noexcept
    {
        if (remaining() < 1)
        {
            return false;
        }
        value = input_[position_++];
        return true;
    }

    [[nodiscard]] bool read_u16(std::uint16_t& value) noexcept
    {
        if (remaining() < 2)
        {
            return false;
        }
        value = read_be16(input_.data() + position_);
        position_ += 2;
        return true;
    }

    [[nodiscard]] bool read_u24(std::uint32_t& value) noexcept
    {
        if (remaining() < 3)
        {
            return false;
        }
        value = read_be24(input_.data() + position_);
        position_ += 3;
        return true;
    }

    [[nodiscard]] std::optional<std::span<const std::uint8_t>> read_bytes(std::size_t size) noexcept
    {
        if (remaining() < size)
        {
            return std::nullopt;
        }
        const auto output = input_.subspan(position_, size);
        position_ += size;
        return output;
    }

    [[nodiscard]] bool skip(std::size_t size) noexcept
    {
        if (remaining() < size)
        {
            return false;
        }
        position_ += size;
        return true;
    }

   private:
    std::span<const std::uint8_t> input_;
    std::size_t position_{0};
};

}    // namespace rv::core

#endif    // REALITY_VISION_BYTE_READER_HPP
