from __future__ import annotations

import importlib
import os
import sys
import types
import unittest
from unittest.mock import patch


class _ProbeMain(types.ModuleType):
    """Fake application module that records when ``app`` is imported."""

    def __init__(self, state: dict[str, bool], events: list[bool]) -> None:
        super().__init__("apps.api.agent_supervisor.main")
        self._state = state
        self._events = events
        self.app_value = object()

    def __getattr__(self, name: str):
        if name == "app":
            self._events.append(self._state["environment_loaded"])
            return self.app_value
        raise AttributeError(name)


class PortableServerStartupTest(unittest.TestCase):
    def _import_with_fake_application(
        self,
    ) -> tuple[types.ModuleType, dict[str, bool], list[bool], _ProbeMain, types.ModuleType | None]:
        state = {"environment_loaded": False}
        events: list[bool] = []
        fake_main = _ProbeMain(state, events)
        sys.modules.pop("apps.api.portable_server", None)
        previous_main = sys.modules.get("apps.api.agent_supervisor.main")
        sys.modules["apps.api.agent_supervisor.main"] = fake_main
        portable = importlib.import_module("apps.api.portable_server")
        return portable, state, events, fake_main, previous_main

    def test_environment_is_loaded_before_application_import(self):
        portable, state, events, fake_main, previous_main = self._import_with_fake_application()
        try:
            with patch.dict(
                os.environ,
                {
                    "AGENT_SUPERVISOR_API_HOST": "127.0.0.1",
                    "AGENT_SUPERVISOR_API_PORT": "8765",
                    "AGENT_SUPERVISOR_OPEN_BROWSER": "false",
                },
                clear=False,
            ), patch.object(
                portable,
                "load_environment_file",
                side_effect=lambda: state.__setitem__("environment_loaded", True),
            ), patch.object(portable, "configure_server_security"), patch.object(portable.uvicorn, "run") as run:
                portable.main()

            self.assertEqual(events, [True])
            run.assert_called_once_with(fake_main.app_value, host="127.0.0.1", port=8765, log_level="info")
        finally:
            sys.modules.pop("apps.api.portable_server", None)
            if previous_main is None:
                sys.modules.pop("apps.api.agent_supervisor.main", None)
            else:
                sys.modules["apps.api.agent_supervisor.main"] = previous_main

    def test_security_failure_stops_before_application_import(self):
        portable, state, events, _fake_main, previous_main = self._import_with_fake_application()
        try:
            with patch.dict(
                os.environ,
                {
                    "AGENT_SUPERVISOR_API_HOST": "127.0.0.1",
                    "AGENT_SUPERVISOR_OPEN_BROWSER": "false",
                },
                clear=False,
            ), patch.object(
                portable,
                "load_environment_file",
                side_effect=lambda: state.__setitem__("environment_loaded", True),
            ), patch.object(
                portable,
                "configure_server_security",
                side_effect=RuntimeError("security configuration failed"),
            ), patch.object(portable.uvicorn, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "security configuration failed"):
                    portable.main()

            self.assertEqual(events, [])
            run.assert_not_called()
        finally:
            sys.modules.pop("apps.api.portable_server", None)
            if previous_main is None:
                sys.modules.pop("apps.api.agent_supervisor.main", None)
            else:
                sys.modules["apps.api.agent_supervisor.main"] = previous_main


if __name__ == "__main__":
    unittest.main()
