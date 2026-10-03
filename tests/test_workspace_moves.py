"""Workspaces survive the project being moved: stale binary paths and build caches."""

from api.workspaces import Workspaces
from output.compiler import _discard_foreign_cache


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


def test_cmake_cache_from_another_location_is_discarded(tmp_path):
    project = tmp_path / "reconstructed"
    build = project / "build"
    build.mkdir(parents=True)

    (build / "CMakeCache.txt").write_text("CMAKE_HOME_DIRECTORY:INTERNAL=F:/Old/workspace/Chess/reconstructed\n")
    _discard_foreign_cache(build, project)
    assert not build.exists()

    build.mkdir()
    (build / "CMakeCache.txt").write_text(f"CMAKE_HOME_DIRECTORY:INTERNAL={project.resolve().as_posix()}\n")
    _discard_foreign_cache(build, project)
    assert (build / "CMakeCache.txt").exists()   # same location: incremental builds keep working
