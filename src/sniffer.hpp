#ifndef REALITY_VISION_SNIFFER_HPP
#define REALITY_VISION_SNIFFER_HPP

#include <cstdint>
#include <span>
#include <string>

namespace rv::sniff
{

enum class status : std::uint8_t
{
    need_more,
    no_match,
    found
};

struct result
{
    status state{status::need_more};
    std::string domain;
};

[[nodiscard]] result inspect_destination(std::span<const std::uint8_t> input);

}    // namespace rv::sniff

#endif
