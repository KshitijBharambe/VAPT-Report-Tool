import io
import unittest
from unittest.mock import patch

import main as runtime_main


class MainRuntimeTests(unittest.TestCase):
    def test_main_reuses_existing_healthy_runtime(self) -> None:
        stdout = io.StringIO()

        with patch("main.shutil.which", return_value="/usr/bin/node"), patch(
            "main._runtime_is_healthy", return_value=True, create=True
        ), patch("main.subprocess.run") as run_mock, patch("sys.stdout", stdout):
            rc = runtime_main.main()

        self.assertEqual(rc, 0)
        run_mock.assert_not_called()
        self.assertIn("already running", stdout.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
