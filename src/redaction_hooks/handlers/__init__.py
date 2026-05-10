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

"""Per-event hook handlers + dispatch table.

Each module in this package implements one Claude Code hook event and
exports a `handle_<event>(data, project_dir)` function returning the
process exit code (0 OK, 2 block).
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .compact import handle_post_compact, handle_pre_compact
from .instructions_loaded import handle_instructions_loaded
from .post_tool_use import handle_post_tool_use
from .post_tool_use_failure import handle_post_tool_use_failure
from .pre_tool_use import handle_pre_tool_use
from .stop import handle_stop
from .user_prompt_submit import handle_user_prompt_submit

__all__ = [
    "dispatch",
    "handle_instructions_loaded",
    "handle_post_compact",
    "handle_post_tool_use",
    "handle_post_tool_use_failure",
    "handle_pre_compact",
    "handle_pre_tool_use",
    "handle_stop",
    "handle_user_prompt_submit",
]


_HandlerFn = Callable[[dict[str, Any], Path | None], int]

_DISPATCH: dict[str, _HandlerFn] = {
    "PreToolUse": handle_pre_tool_use,
    "PostToolUse": handle_post_tool_use,
    "PostToolUseFailure": handle_post_tool_use_failure,
    "UserPromptSubmit": handle_user_prompt_submit,
    "PreCompact": handle_pre_compact,
    "PostCompact": handle_post_compact,
    "InstructionsLoaded": handle_instructions_loaded,
    "Stop": handle_stop,
    "SubagentStop": handle_stop,
}


def dispatch(event: str, data: dict[str, Any], project_dir: Path | None) -> int:
    """Route a hook payload to its handler. Unknown events allow continue."""
    handler = _DISPATCH.get(event)
    if handler is None:
        import json

        json.dump({"continue": True}, sys.stdout)
        return 0
    return handler(data, project_dir)
