import os
import stat
import tempfile
import unittest
from unittest.mock import AsyncMock
from unittest.mock import patch

import tsdfileapi.access as access
from tsdfileapi.access import chmod
from tsdfileapi.access import chown
from tsdfileapi.access import ensure_access
from tsdfileapi.access import ensure_parent_access
from tsdfileapi.access import retry_on_permission_error
from tsdfileapi.access import temporary_write_access


class TestAccessHelpers(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self.tmp.name)
        self.directory = os.path.join(self.root, "dir")
        os.mkdir(self.directory, 0o700)
        self.file = os.path.join(self.directory, "file")
        with open(self.file, "w") as f:
            f.write("data")
        os.chmod(self.file, 0o600)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    async def test_ensure_access_is_noop_when_accessible(self) -> None:
        with (
            patch.object(
                access.aio.os, "access", AsyncMock(return_value=True)
            ) as mocked_access,
            patch.object(access, "chmod", AsyncMock()) as mocked_chmod,
        ):
            await ensure_access(self.file, os.R_OK)
        mocked_access.assert_awaited_once_with(self.file, os.R_OK)
        mocked_chmod.assert_not_awaited()

    async def test_ensure_access_adds_group_and_other_read(self) -> None:
        st = os.stat(self.file)
        with (
            patch.object(access.aio.os, "access", AsyncMock(return_value=False)),
            patch.object(access, "chmod", AsyncMock()) as mocked_chmod,
        ):
            await ensure_access(self.file, os.R_OK)
        expected = stat.S_IMODE(st.st_mode) | stat.S_IRGRP | stat.S_IROTH
        mocked_chmod.assert_awaited_once()
        path, mode = mocked_chmod.await_args.args
        self.assertEqual(path, self.file)
        self.assertEqual(stat.S_IMODE(mode), expected)

    async def test_ensure_access_adds_execute_for_directories(self) -> None:
        st = os.stat(self.directory)
        with (
            patch.object(access.aio.os, "access", AsyncMock(return_value=False)),
            patch.object(access, "chmod", AsyncMock()) as mocked_chmod,
        ):
            await ensure_access(self.directory, os.R_OK)
        expected = (
            stat.S_IMODE(st.st_mode)
            | stat.S_IRGRP
            | stat.S_IROTH
            | stat.S_IXGRP
            | stat.S_IXOTH
        )
        mocked_chmod.assert_awaited_once()
        _, mode = mocked_chmod.await_args.args
        self.assertEqual(stat.S_IMODE(mode), expected)

    async def test_ensure_parent_access_stops_at_root(self) -> None:
        nested = os.path.join(self.directory, "nested")
        os.mkdir(nested, 0o700)
        target = os.path.join(nested, "file")
        open(target, "w").close()
        with (
            patch.object(access.aio.os, "access", AsyncMock(return_value=False)),
            patch.object(access, "chmod", AsyncMock()) as mocked_chmod,
        ):
            await ensure_parent_access(target, root=self.root)
        touched = [call.args[0] for call in mocked_chmod.await_args_list]
        self.assertEqual(touched, [nested, self.directory, self.root])
        self.assertNotIn(os.path.dirname(self.root), touched)

    async def test_temporary_write_access_restores_mode(self) -> None:
        original = stat.S_IMODE(os.stat(self.directory).st_mode)
        with patch.object(access.aio.os, "access", AsyncMock(return_value=False)):
            async with temporary_write_access(self.directory):
                during = stat.S_IMODE(os.stat(self.directory).st_mode)
                self.assertNotEqual(during, original)
        after = stat.S_IMODE(os.stat(self.directory).st_mode)
        self.assertEqual(after, original)

    async def test_temporary_write_access_does_not_chmod_when_writable(self) -> None:
        with (
            patch.object(access.aio.os, "access", AsyncMock(return_value=True)),
            patch.object(access, "chmod", AsyncMock()) as mocked_chmod,
        ):
            async with temporary_write_access(self.directory):
                pass
        mocked_chmod.assert_not_awaited()

    async def test_retry_on_permission_error_retries_once(self) -> None:
        calls = []

        async def operation():
            calls.append(1)
            if len(calls) == 1:
                raise PermissionError
            return "ok"

        with patch.object(access, "ensure_access", AsyncMock()) as mocked_ensure:
            result = await retry_on_permission_error(operation, self.file, mode=os.R_OK)
        self.assertEqual(result, "ok")
        self.assertEqual(len(calls), 2)
        mocked_ensure.assert_awaited_once_with(
            self.file, os.R_OK, sudo=False, recursive=False
        )

    async def test_chmod_uses_sudo_fallback(self) -> None:
        with (
            patch.object(
                access.aio.os, "chmod", AsyncMock(side_effect=PermissionError)
            ),
            patch.object(access, "asystem", AsyncMock()) as mocked_asystem,
        ):
            await chmod(self.file, 0o644, sudo=True)
        mocked_asystem.assert_awaited_once_with(["sudo", "chmod", "644", self.file])

    async def test_chmod_without_sudo_raises(self) -> None:
        with patch.object(
            access.aio.os, "chmod", AsyncMock(side_effect=PermissionError)
        ):
            with self.assertRaises(PermissionError):
                await chmod(self.file, 0o644)

    async def test_chown_uses_sudo_fallback(self) -> None:
        with (
            patch.object(
                access.aio.os, "chown", AsyncMock(side_effect=PermissionError)
            ),
            patch.object(access, "asystem", AsyncMock()) as mocked_asystem,
        ):
            await chown(self.file, 1000, 1000, sudo=True)
        mocked_asystem.assert_awaited_once_with(
            ["sudo", "chown", "1000:1000", self.file]
        )

    async def test_chown_without_sudo_raises(self) -> None:
        with patch.object(
            access.aio.os, "chown", AsyncMock(side_effect=PermissionError)
        ):
            with self.assertRaises(PermissionError):
                await chown(self.file, 1000, 1000)
