#ifndef REALITY_VISION_BYTE_QUEUE_HPP
#define REALITY_VISION_BYTE_QUEUE_HPP

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <algorithm>

#include <boost/system/errc.hpp>
#include <boost/system/error_code.hpp>

namespace rv::core
{

class byte_queue
{
   public:
    explicit byte_queue(std::size_t limit = 1U << 20) : size_limit_(limit) {}

    [[nodiscard]] bool empty() const noexcept { return size() == 0; }
    [[nodiscard]] std::size_t size() const noexcept { return storage_.size() - read_offset_; }
    [[nodiscard]] std::span<const std::uint8_t> data() const noexcept { return std::span<const std::uint8_t>(storage_).subspan(read_offset_); }

    void append(std::span<const std::uint8_t> input, boost::system::error_code& ec)
    {
        if (input.size() > size_limit_ - size())
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            return;
        }
        compact_if_needed(input.size());
        storage_.insert(storage_.end(), input.begin(), input.end());
    }

    std::size_t copy_to(std::span<std::uint8_t> output)
    {
        const auto count = std::min(output.size(), size());
        if (count != 0)
        {
            std::memcpy(output.data(), storage_.data() + read_offset_, count);
            consume(count);
        }
        return count;
    }

    void consume(std::size_t count) noexcept
    {
        count = std::min(count, size());
        read_offset_ += count;
        if (read_offset_ == storage_.size())
        {
            clear();
        }
    }

    [[nodiscard]] std::vector<std::uint8_t> take(std::size_t count)
    {
        count = std::min(count, size());
        if (count == 0)
        {
            return {};
        }
        const auto bytes = data().first(count);
        std::vector<std::uint8_t> result(bytes.begin(), bytes.end());
        consume(count);
        return result;
    }

    void clear() noexcept
    {
        storage_.clear();
        read_offset_ = 0;
    }

   private:
    void compact_if_needed(std::size_t incoming)
    {
        if (read_offset_ != 0 && storage_.capacity() - storage_.size() < incoming)
        {
            storage_.erase(storage_.begin(), storage_.begin() + static_cast<std::ptrdiff_t>(read_offset_));
            read_offset_ = 0;
        }
    }

    std::vector<std::uint8_t> storage_;
    std::size_t read_offset_{0};
    std::size_t size_limit_;
};

}    // namespace rv::core

#endif    // REALITY_VISION_BYTE_QUEUE_HPP
