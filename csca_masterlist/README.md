# CSCA Master List

This directory contains the ICAO master list file that is bundled with the Docker image.

**Current file:** `allowlist.ml`
- Source: https://github.com/zenopie/csca-trust-store
- Contains: 520 CSCA certificates from various countries
- Last updated: Check git history

## Updating the Master List

To update the master list:

1. Download the latest `allowlist.ml` from the trust store repository
2. Replace the file in this directory
3. Delete `.csca_cache/` directory (will be regenerated on startup)
4. Commit and rebuild Docker image

The certificates are automatically extracted to `.csca_cache/certs/` on application startup.
