"""Hatchling build hook: compile the Go bridge and tag the wheel per-platform."""

import os
import subprocess
import sysconfig

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        if self.target_name != "wheel":
            return
        subprocess.run(["make", "build"], check=True, cwd=self.root)
        build_data["pure_python"] = False
        # The wheel is Python-version independent but platform specific.
        # OPA_BINDINGS_PLAT overrides the tag in CI (e.g. macosx_11_0_arm64).
        plat = os.environ.get("OPA_BINDINGS_PLAT") or (
            sysconfig.get_platform().replace("-", "_").replace(".", "_")
        )
        build_data["tag"] = f"py3-none-{plat}"
