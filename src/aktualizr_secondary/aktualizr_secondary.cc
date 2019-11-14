#include "aktualizr_secondary.h"

#include <sys/types.h>
#include <memory>

#include "logging/logging.h"
#ifdef BUILD_OSTREE
#include "package_manager/ostreemanager.h"  // TODO: Hide behind PackageManagerInterface
#endif
#include "socket_server.h"
#include "unordered_map"
#include "uptane/fetcher.h"
#include "utilities/utils.h"

class SecondaryMetadataFetcher : public Uptane::IFetcher {
 public:
  SecondaryMetadataFetcher(const Uptane::RawMetaPack& meta_pack) {
    director_metadata_ = {{Uptane::Role::ROOT, meta_pack.director_root},
                          {Uptane::Role::TARGETS, meta_pack.director_targets}};

    image_metadata_ = {
        {Uptane::Role::ROOT, meta_pack.image_root},
        {Uptane::Role::TIMESTAMP, meta_pack.image_timestamp},
        {Uptane::Role::SNAPSHOT, meta_pack.image_snapshot},
        {Uptane::Role::TARGETS, meta_pack.image_targets},
    };
  }

  virtual bool fetchRole(std::string* result, int64_t maxsize, Uptane::RepositoryType repo, const Uptane::Role& role,
                         Uptane::Version version);
  virtual bool fetchLatestRole(std::string* result, int64_t maxsize, Uptane::RepositoryType repo,
                               const Uptane::Role& role);

 private:
  bool getRoleMetadata(std::string* result, const Uptane::RepositoryType& repo, const Uptane::Role& role);

 private:
  std::unordered_map<std::string, std::string> director_metadata_;
  std::unordered_map<std::string, std::string> image_metadata_;
};

class SecondaryAdapter : public Uptane::SecondaryInterface {
 public:
  SecondaryAdapter(AktualizrSecondary& sec) : secondary(sec) {}
  ~SecondaryAdapter() override = default;

  Uptane::EcuSerial getSerial() override { return secondary.getSerialResp(); }
  Uptane::HardwareIdentifier getHwId() override { return secondary.getHwIdResp(); }
  PublicKey getPublicKey() override { return secondary.getPublicKeyResp(); }
  Json::Value getManifest() override { return secondary.getManifestResp(); }
  bool putMetadata(const Uptane::RawMetaPack& meta_pack) override { return secondary.putMetadataResp(meta_pack); }
  int32_t getRootVersion(bool director) override { return secondary.getRootVersionResp(director); }
  bool putRoot(const std::string& root, bool director) override { return secondary.putRootResp(root, director); }
  bool sendFirmware(const std::shared_ptr<std::string>& data) override {
    return secondary.AktualizrSecondary::sendFirmwareResp(data);
  }

 private:
  AktualizrSecondary& secondary;
};

AktualizrSecondary::AktualizrSecondary(const AktualizrSecondaryConfig& config,
                                       const std::shared_ptr<INvStorage>& storage)
    : AktualizrSecondaryCommon(config, storage),
      socket_server_(std_::make_unique<SecondaryAdapter>(*this), SocketFromPort(config.network.port)) {
  // note: we don't use TlsConfig here and supply the default to
  // KeyManagerConf. Maybe we should figure a cleaner way to do that
  // (split KeyManager?)
  if (!uptaneInitialize()) {
    LOG_ERROR << "Failed to initialize";
    return;
  }
}

void AktualizrSecondary::run() {
  connectToPrimary();
  socket_server_.Run();
}

void AktualizrSecondary::stop() { /* TODO? */
}

Uptane::EcuSerial AktualizrSecondary::getSerialResp() const { return ecu_serial_; }

Uptane::HardwareIdentifier AktualizrSecondary::getHwIdResp() const { return hardware_id_; }

PublicKey AktualizrSecondary::getPublicKeyResp() const { return keys_.UptanePublicKey(); }

Json::Value AktualizrSecondary::getManifestResp() const {
  Json::Value manifest = pacman->getManifest(getSerialResp());

  return keys_.signTuf(manifest);
}

bool AktualizrSecondary::putMetadataResp(const Uptane::RawMetaPack& meta_pack) {
  /**
   *  5.4.4.2. Full verification  https://uptane.github.io/uptane-standard/uptane-standard.html#metadata_verification
   */

  // 1. Load and verify the current time or the most recent securely attested time.
  // We trust our time, In this ECU we trust :)

  SecondaryMetadataFetcher metadataFetcher(meta_pack);

  TimeStamp now(TimeStamp::Now());

  // 2. Download and check the Root metadata file from the Director repository, following the procedure in
  // Section 5.4.4.3. 5.4.4.3. How to check Root metadata Not supported: 3. Download and check the Timestamp metadata
  // file from the Director repository, following the procedure in Section 5.4.4.4. Not supported: 4. Download and check
  // the Snapshot metadata file from the Director repository, following the procedure in Section 5.4.4.5.
  // 5. Download and check the Targets metadata file from the Director repository, following the procedure in
  // Section 5.4.4.6.
  if (!director_repo_.updateMeta(*storage_, metadataFetcher)) {
    LOG_ERROR << "Failed to update director metadata: " << director_repo_.getLastException().what();
    return false;
  }

  auto targetsForThisEcu = director_repo_.getTargets(getSerial());

  if (targetsForThisEcu.size() != 1) {
    LOG_ERROR << "Invalid number of targets (should be one): " << targetsForThisEcu.size();
    return false;
  }

  // 6. Download and check the Root metadata file from the Image repository, following the procedure in Section 5.4.4.3.
  // 7. Download and check the Timestamp metadata file from the Image repository, following the procedure in
  // Section 5.4.4.4.
  // 8. Download and check the Snapshot metadata file from the Image repository, following the procedure in
  // Section 5.4.4.5.
  // 9. Download and check the top-level Targets metadata file from the Image repository, following the procedure in
  // Section 5.4.4.6.
  if (!image_repo_.updateMeta(*storage_, metadataFetcher)) {
    LOG_ERROR << "Failed to update image metadata: " << image_repo_.getLastException().what();
    return false;
  }

  // 10. Verify that Targets metadata from the Director and Image repositories match.
  if (!(director_repo_.getTargets() == *image_repo_.getTargets())) {
    LOG_ERROR << "Targets metadata from the Director and Image repositories DOES NOT match ";
    return false;
  }

  return true;
}

int32_t AktualizrSecondary::getRootVersionResp(bool director) const {
  std::string root_meta;
  if (!storage_->loadLatestRoot(&root_meta,
                                (director) ? Uptane::RepositoryType::Director() : Uptane::RepositoryType::Image())) {
    LOG_ERROR << "Could not load root metadata";
    return -1;
  }

  return Uptane::extractVersionUntrusted(root_meta);
}

bool AktualizrSecondary::putRootResp(const std::string& root, bool director) {
  (void)root;
  (void)director;
  LOG_ERROR << "putRootResp is not implemented yet";
  return false;
}

bool AktualizrSecondary::sendFirmwareResp(const std::shared_ptr<std::string>& firmware) {
  auto targetsForThisEcu = director_repo_.getTargets(getSerial());

  if (targetsForThisEcu.size() != 1) {
    LOG_ERROR << "Invalid number of targets (should be one): " << targetsForThisEcu.size();
    return false;
  }
  auto targetToApply = targetsForThisEcu[0];

  std::string treehub_server;

  if (targetToApply.IsOstree()) {
    // this is the ostree specific case
    try {
      std::string ca, cert, pkey, server_url;
      extractCredentialsArchive(*firmware, &ca, &cert, &pkey, &treehub_server);
      keys_.loadKeys(&ca, &cert, &pkey);
      boost::trim(server_url);
      treehub_server = server_url;
    } catch (std::runtime_error& exc) {
      LOG_ERROR << exc.what();

      return false;
    }
  }

  data::InstallationResult install_res;

  if (targetToApply.IsOstree()) {
#ifdef BUILD_OSTREE
    install_res = OstreeManager::pull(config_.pacman.sysroot, treehub_server, keys_, targetToApply);

    if (install_res.result_code.num_code != data::ResultCode::Numeric::kOk) {
      LOG_ERROR << "Could not pull from OSTree (" << install_res.result_code.toString()
                << "): " << install_res.description;
      return false;
    }
#else
    LOG_ERROR << "Could not pull from OSTree. Aktualizr was built without OSTree support!";
    return false;
#endif
  } else if (pacman->name() == "debian") {
    // TODO save debian package here.
    LOG_ERROR << "Installation of non ostree images is not suppotrted yet.";
    return false;
  }

  install_res = pacman->install(targetToApply);
  if (install_res.result_code.num_code != data::ResultCode::Numeric::kOk) {
    LOG_ERROR << "Could not install target (" << install_res.result_code.toString() << "): " << install_res.description;
    return false;
  }
  storage_->saveInstalledVersion(getSerialResp().ToString(), targetToApply, InstalledVersionUpdateMode::kCurrent);
  return true;
}

void AktualizrSecondary::extractCredentialsArchive(const std::string& archive, std::string* ca, std::string* cert,
                                                   std::string* pkey, std::string* treehub_server) {
  {
    std::stringstream as(archive);
    *ca = Utils::readFileFromArchive(as, "ca.pem");
  }
  {
    std::stringstream as(archive);
    *cert = Utils::readFileFromArchive(as, "client.pem");
  }
  {
    std::stringstream as(archive);
    *pkey = Utils::readFileFromArchive(as, "pkey.pem");
  }
  {
    std::stringstream as(archive);
    *treehub_server = Utils::readFileFromArchive(as, "server.url", true);
  }
}

void AktualizrSecondary::connectToPrimary() {
  Socket socket(config_.network.primary_ip, config_.network.primary_port);

  if (socket.bind(config_.network.port) != 0) {
    LOG_ERROR << "Failed to bind a connection socket to the secondary's port";
    return;
  }

  if (socket.connect() == 0) {
    LOG_INFO << "Connected to Primary, sending info about this secondary...";
    socket_server_.HandleOneConnection(socket.getFD());
  } else {
    LOG_INFO << "Failed to connect to Primary";
  }
}

bool SecondaryMetadataFetcher::fetchRole(std::string* result, int64_t maxsize, Uptane::RepositoryType repo,
                                         const Uptane::Role& role, Uptane::Version version) {
  (void)maxsize;
  (void)version;

  return getRoleMetadata(result, repo, role);
}

bool SecondaryMetadataFetcher::fetchLatestRole(std::string* result, int64_t maxsize, Uptane::RepositoryType repo,
                                               const Uptane::Role& role) {
  (void)maxsize;
  return getRoleMetadata(result, repo, role);
}

bool SecondaryMetadataFetcher::getRoleMetadata(std::string* result, const Uptane::RepositoryType& repo,
                                               const Uptane::Role& role) {
  std::unordered_map<std::string, std::string>* metadata_map = nullptr;

  if (repo == Uptane::RepositoryType::Director()) {
    metadata_map = &director_metadata_;
  } else if (repo == Uptane::RepositoryType::Image()) {
    metadata_map = &image_metadata_;
  }

  if (metadata_map == nullptr) {
    return false;
  }

  auto found_meta_it = metadata_map->find(role.ToString());
  if (found_meta_it == metadata_map->end()) {
    return false;
  }

  *result = found_meta_it->second;
  return true;
}
