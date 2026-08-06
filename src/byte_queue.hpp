#ifndef REALITY_VISION_BYTE_QUEUE_HPP
#define REALITY_VISION_BYTE_QUEUE_HPP

#include <boost/system/errc.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace rv::core
{

class byte_queue
{
public:
    explicit byte_queue(std::size_t limit = 1U << 20) : limit_(limit) {}

    [[nodiscard]] bool empty() const noexcept { return size() == 0; }
    [[nodiscard]] std::size_t size() const noexcept { return storage_.size() - begin_; }
    [[nodiscard]] std::span<const std::uint8_t> data() const noexcept
    {
        return {storage_.data() + begin_, size()};
    }

    [[nodiscard]] bool append(std::span<const std::uint8_t> input, boost::system::error_code& ec)
    {
        ec.clear();
        if (input.size() > limit_ - size())
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            return false;
        }
        compact_if_needed(input.size());
        storage_.insert(storage_.end(), input.begin(), input.end());
        return true;
    }

    std::size_t copy_to(std::span<std::uint8_t> output)
    {
        const auto count = std::min(output.size(), size());
        if (count != 0)
        {
            std::memcpy(output.data(), storage_.data() + begin_, count);
            consume(count);
        }
        return count;
    }

    void consume(std::size_t count) noexcept
    {
        count = std::min(count, size());
        begin_ += count;
        if (begin_ == storage_.size())
        {
            clear();
        }
    }

    [[nodiscard]] std::vector<std::uint8_t> take(std::size_t count)
    {
        count = std::min(count, size());
        std::vector<std::uint8_t> result(data().begin(), data().begin() + static_cast<std::ptrdiff_t>(count));
        consume(count);
        return result;
    }

    void clear() noexcept
    {
        storage_.clear();
        begin_ = 0;
    }

private:
    void compact_if_needed(std::size_t incoming)
    {
        if (begin_ != 0 && storage_.capacity() - storage_.size() < incoming)
        {
            storage_.erase(storage_.begin(), storage_.begin() + static_cast<std::ptrdiff_t>(begin_));
            begin_ = 0;
        }
    }

    std::vector<std::uint8_t> storage_;
    std::size_t begin_{0};
    std::size_t limit_;
};

} // namespace rv::core

#endif
