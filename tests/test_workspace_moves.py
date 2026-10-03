"""Workspaces survive the project being moved: stale binary paths resolve by file name."""

from api.workspaces import Workspaces


def test_resolve_binary_after_move(tmp_path):
    bins = tmp_path / "TestBinaries"
    bins.mkdir()
    (bins / "Chess.exe").write_bytes(b"MZ")
    ws = Workspaces(lambda: tmp_path / "workspace", binary_dirs=[tmp_path / "binaries", bins])

    moved_from = r"F:\Old\Location\TestBinaries\Chess.exe"
    assert ws.resolve_binary(moved_from) == (str(bins / "Chess.exe"), True)
    assert ws.resolve_binary(str(bins / "Chess.exe")) == (str(bins / "Chess.exe"), True)
    assert ws.resolve_binary(r"F:\Old\Gone.exe") == (r"F:\Old\Gone.exe", False)
    assert ws.resolve_binary("") == ("", False)
