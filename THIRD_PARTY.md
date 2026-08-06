# Third-party references

This project interoperates with and was developed by studying the wire behavior of:

- [XTLS/Xray-core](https://github.com/XTLS/Xray-core), MPL-2.0;
- [refraction-networking/uTLS](https://github.com/refraction-networking/utls), BSD-3-Clause;
- [XTLS/REALITY](https://github.com/XTLS/REALITY), MPL-2.0;
- [BoringSSL](https://boringssl.googlesource.com/boringssl/), ISC-style and component licenses;
- [Boost](https://www.boost.org/), Boost Software License 1.0;
- [spdlog](https://github.com/gabime/spdlog), MIT.

Exact tested compatibility revisions are recorded in `docs/COMPATIBILITY.md`. Third-party source
is not copied into this repository, and this project's CMake does not download or build it.
