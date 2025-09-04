#pragma once

#include "envoy/http/filter.h"
#include "envoy/server/filter_config.h"

#include <string>

namespace Envoy {
namespace Http {

// Minimal stub: on first decodeHeaders, attempt to get TLS exporter material and inject header.
class PchExporterFilter : public StreamDecoderFilter { // NOLINT
public:
  PchExporterFilter() = default;

  // StreamDecoderFilter
  FilterHeadersStatus decodeHeaders(RequestHeaderMap& headers, bool) override;
  void setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) override { callbacks_ = &callbacks; }
  FilterDataStatus decodeData(Buffer::Instance&, bool) override { return FilterDataStatus::Continue; }
  FilterTrailersStatus decodeTrailers(RequestTrailerMap&) override { return FilterTrailersStatus::Continue; }
  void onDestroy() override {}

private:
  StreamDecoderFilterCallbacks* callbacks_{nullptr};
};

class PchExporterFilterFactory : public Server::Configuration::NamedHttpFilterConfigFactory { // NOLINT
public:
  // Create empty Proto config for v2 compatibility (unused).
  ProtobufTypes::MessagePtr createEmptyConfigProto() override { return nullptr; }
  std::string name() const override { return "pch_exporter"; }
  Http::FilterFactoryCb createFilterFactoryFromProto(const Protobuf::Message&, const std::string&, Server::Configuration::FactoryContext&) override;
  Http::FilterFactoryCb createFilterFactoryFromProtoWithServerContext(const Protobuf::Message& proto_config, const std::string& stats_prefix, Server::Configuration::ServerFactoryContext& context) override {
    return createFilterFactoryFromProto(proto_config, stats_prefix, context);
  }
};

} // namespace Http
} // namespace Envoy
