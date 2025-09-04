#include "pch_exporter_filter.h"

#include "envoy/network/connection.h"
#include "source/common/common/base64.h"
#include "source/common/http/utility.h"

namespace Envoy { namespace Http {

namespace {
constexpr absl::string_view kHeaderName = "x-tls-exporter"; // lower-case; Envoy will canonicalize
constexpr absl::string_view kLabel = "EXPORTER_PCH";
constexpr size_t kLen = 32;
}

FilterHeadersStatus PchExporterFilter::decodeHeaders(RequestHeaderMap& headers, bool) {
  if (!callbacks_) {
    return FilterHeadersStatus::Continue;
  }
  auto* stream_info = &callbacks_->streamInfo();
  auto ssl = stream_info->downstreamSslConnection();
  if (ssl) {
    // Attempt to compute exporter; dummy context value empty per RFC usage when context not needed.
    std::array<uint8_t, kLen> out{};
    const int rc = ssl->keyExport(kLabel, "", out.data(), out.size());
    if (rc == 1) {
      std::string b64 = Base64::encode(out.data(), out.size(), /*add_padding=*/true);
      headers.addCopy(LowerCaseString(std::string(kHeaderName)), b64);
    }
  }
  return FilterHeadersStatus::Continue;
}

Http::FilterFactoryCb PchExporterFilterFactory::createFilterFactoryFromProto(
    const Protobuf::Message&, const std::string&, Server::Configuration::FactoryContext&) {
  return [](Http::FilterChainFactoryCallbacks& callbacks) {
    callbacks.addStreamDecoderFilter(std::make_shared<PchExporterFilter>());
  };
}

// Static registration (guard with build flag in build system; here unconditional stub)
REGISTER_FACTORY(PchExporterFilterFactory, Server::Configuration::NamedHttpFilterConfigFactory);

}} // namespace Envoy::Http
