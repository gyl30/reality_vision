#ifndef REALITY_VISION_SNIFFER_HPP
#define REALITY_VISION_SNIFFER_HPP

#include <span>
#include <string>
#include <cstdint>

namespace rv::sniff
{

enum class status : std::uint8_t
{
    kNeedMore,
    kNoMatch,
    kFound
};

struct result
{
    status state{status::kNeedMore};
    std::string domain;
};

[[nodiscard]] result inspect_destination(std::span<const std::uint8_t> input);

}    // namespace rv::sniff

#endif    // REALITY_VISION_SNIFFER_HPP
