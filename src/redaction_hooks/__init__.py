# Copyright 2025 Lars Marowsky-Brée <lars@marowsky-bree.eu>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Claude Code redaction hooks for preventing secrets and PII leakage."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("claude-code-redaction-hooks")
except PackageNotFoundError:  # not installed (e.g. running from a sdist tarball)
    __version__ = "0.0.0+unknown"
