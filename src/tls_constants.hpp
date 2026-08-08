#ifndef REALITY_VISION_TLS_CONSTANTS_HPP
#define REALITY_VISION_TLS_CONSTANTS_HPP

#include <cstddef>
#include <cstdint>

namespace rv::tls
{

inline constexpr std::size_t kRecordHeaderSize = 5;
inline constexpr std::size_t kHandshakeHeaderSize = 4;
inline constexpr std::size_t kRandomSize = 32;
inline constexpr std::size_t kX25519KeyShareSize = 32;
inline constexpr std::size_t kMaximumHandshakeBodyLength = (1U << 24U) - 1U;
inline constexpr std::size_t kAeadTagSize = 16;
inline constexpr std::size_t kMaximumPlaintextSize = 1U << 14U;
inline constexpr std::size_t kMaximumInnerPlaintextSize = kMaximumPlaintextSize + 1U;
inline constexpr std::size_t kMaximumCiphertextSize = kMaximumPlaintextSize + 256U;
inline constexpr std::size_t kMaximumHandshakeMessageSize = 1U << 20U;

inline constexpr std::uint8_t kRecordChangeCipherSpec = 20;
inline constexpr std::uint8_t kRecordAlert = 21;
inline constexpr std::uint8_t kRecordHandshake = 22;
inline constexpr std::uint8_t kRecordApplicationData = 23;

inline constexpr std::uint8_t kHandshakeClientHello = 1;
inline constexpr std::uint8_t kHandshakeServerHello = 2;
inline constexpr std::uint8_t kHandshakeNewSessionTicket = 4;
inline constexpr std::uint8_t kHandshakeEncryptedExtensions = 8;
inline constexpr std::uint8_t kHandshakeCertificate = 11;
inline constexpr std::uint8_t kHandshakeCertificateVerify = 15;
inline constexpr std::uint8_t kHandshakeFinished = 20;
inline constexpr std::uint8_t kHandshakeKeyUpdate = 24;

inline constexpr std::uint16_t kLegacyVersion = 0x0303;
inline constexpr std::uint16_t kTls13Version = 0x0304;
inline constexpr std::uint16_t kExtensionServerName = 0x0000;
inline constexpr std::uint16_t kExtensionSupportedVersions = 0x002b;
inline constexpr std::uint16_t kExtensionKeyShare = 0x0033;
inline constexpr std::uint16_t kNamedGroupX25519 = 0x001d;
inline constexpr std::uint16_t kNamedGroupSecp256r1 = 0x0017;
inline constexpr std::uint8_t kNullCompressionMethod = 0;

}    // namespace rv::tls

#endif    // REALITY_VISION_TLS_CONSTANTS_HPP
