# Third-party references

This project interoperates with and was developed by studying the wire behavior of:

- [XTLS/Xray-core](https://github.com/XTLS/Xray-core), MPL-2.0;
- [refraction-networking/uTLS](https://github.com/refraction-networking/utls), BSD-3-Clause;
- [XTLS/REALITY](https://github.com/XTLS/REALITY), MPL-2.0;
- [BoringSSL](https://boringssl.googlesource.com/boringssl/), ISC-style and component licenses;
- [Boost](https://www.boost.org/), Boost Software License 1.0;
- [heiher/lwip](https://github.com/heiher/lwip), 3-Clause BSD license;
- [spdlog](https://github.com/gabime/spdlog), MIT.

Exact tested compatibility revisions are recorded in `docs/COMPATIBILITY.md`. Third-party source
is kept in Git submodules where the build requires source integration. The lwIP submodule is
fixed to commit `07dbf162c718cc78ddedb9e67c6ebd17065eaf13` and is built as `rv_lwip`.
