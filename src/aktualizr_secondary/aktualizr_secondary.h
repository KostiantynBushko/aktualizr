#ifndef AKTUALIZR_SECONDARY_H
#define AKTUALIZR_SECONDARY_H

#include <memory>

#include "aktualizr_secondary_common.h"
#include "aktualizr_secondary_config.h"
#include "aktualizr_secondary_interface.h"
#include "crypto/keymanager.h"
#include "socket_server.h"
#include "storage/invstorage.h"
#include "uptane/tuf.h"
#include "utilities/types.h"
#include "utilities/utils.h"

class AktualizrSecondary : public AktualizrSecondaryInterface, private AktualizrSecondaryCommon {
 public:
  AktualizrSecondary(const AktualizrSecondaryConfig& config, const std::shared_ptr<INvStorage>& storage);
  void run() override;
  void stop() override;

  // implementation of primary's SecondaryInterface
  Uptane::EcuSerial getSerialResp() const;
  Uptane::HardwareIdentifier getHwIdResp() const;
  PublicKey getPublicKeyResp() const;
  Json::Value getManifestResp() const;
  bool putMetadataResp(const Uptane::RawMetaPack& meta_pack);
  int32_t getRootVersionResp(bool director) const;
  // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
  bool putRootResp(const std::string& root, bool director);
  bool sendFirmwareResp(const std::shared_ptr<std::string>& firmware);

  static void extractCredentialsArchive(const std::string& archive, std::string* ca, std::string* cert,
                                        std::string* pkey, std::string* treehub_server);

 private:
  void connectToPrimary();

 private:
  SocketServer socket_server_;
};

#endif  // AKTUALIZR_SECONDARY_H
