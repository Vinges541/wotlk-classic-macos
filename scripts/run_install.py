"""Pinned CASC installer, independent of the current Battle.net product version."""

import importlib
import os
from pathlib import Path

state = Path(os.environ["WRATH_STATE"])
os.environ["CASCETTE_CACHE_DIR"] = str(state / "cache/casc")
os.environ["CASCETTE_CONFIG_DIR"] = str(state / "cache/casc-config")
os.environ["CASCETTE_DATA_DIR"] = str(state / "cache/casc-metadata")
from cascette_tools.core.cdn import CDNClient
from cascette_tools.__main__ import main
from casc_batch import install_overrides


class WrathCDNClient(CDNClient):
    def ensure_initialized(self):
        if self.product.value != "wow_classic":
            raise ValueError("Unsupported product")
        self.cdn_path = "tpr/wow"
        self.cdn_hosts = ["casc.wago.tools"]
        self.cdn_servers = ["https://casc.wago.tools"]
        self._initialized = True


module = importlib.import_module("cascette_tools.commands.install")
module.CDNClient = WrathCDNClient
install_overrides(module)
if __name__ == "__main__":
    main()
