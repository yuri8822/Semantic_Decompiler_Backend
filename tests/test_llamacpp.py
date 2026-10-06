"""The llama.cpp launcher: command line, model discovery, and the server lifecycle (with a fake server process)."""

import socket
import sys
import time

import pytest
from fastapi.testclient import TestClient

import settings as settings_mod
from api.app import create_app
from api.jobs import JobManager
from llm import llamacpp_server
from llm.llamacpp_server import LlamaServer, LlamaServerError, build_command, find_models
from settings import LlamaServerSettings, Settings

# Stands in for llama.cpp: /health answers 503 while "loading", then 200.
FAKE_SERVER = r'''
import sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer
port, load_seconds, exit_code = int(sys.argv[1]), float(sys.argv[2]), int(sys.argv[3])
if exit_code:
    print("error: failed to load model", flush=True)
    sys.exit(exit_code)
started = time.monotonic()
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        ready = time.monotonic() - started >= load_seconds
        self.send_response(200 if ready or self.path != "/health" else 503)
        self.end_headers()
        self.wfile.write(b"{}")
    def log_message(self, *a):
        pass
print("server listening", flush=True)
HTTPServer(("127.0.0.1", port), H).serve_forever()
'''


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def fake(tmp_path, monkeypatch):
    """Settings pointing at a fake server; returns (settings, set_behaviour(load_seconds, exit_code))."""
    script = tmp_path / "fake_llama.py"
    script.write_text(FAKE_SERVER)
    model = tmp_path / "tiny.gguf"
    model.write_bytes(b"GGUF")
    port = free_port()
    behaviour = {"load": 0.5, "exit": 0}
    monkeypatch.setattr(llamacpp_server, "build_command", lambda exe, cfg, host, p: [
        sys.executable, str(script), str(p), str(behaviour["load"]), str(behaviour["exit"])])
    s = Settings().with_overrides({
        "workspace_dir": str(tmp_path / "ws"),
        "llm": {"provider": "llamacpp", "llamacpp": {"base_url": f"http://localhost:{port}/v1"}},
        "llamacpp_server": {"executable": sys.executable, "model_path": str(model), "load_timeout_seconds": 20},
    })
    return s, lambda load=0.5, exit=0: behaviour.update(load=load, exit=exit)


def test_command_line():
    cfg = LlamaServerSettings(model_path=r"C:\models\m.gguf", thinking="off", extra_args='--threads 8 --chat-template-file "C:\\t x.jinja"')
    cmd = build_command(r"C:\bin\llama.exe", cfg, "127.0.0.1", 8080)
    assert cmd[:2] == [r"C:\bin\llama.exe", "serve"]
    assert cmd[cmd.index("--model") + 1] == r"C:\models\m.gguf" and cmd[cmd.index("--port") + 1] == "8080"
    assert "--reasoning-budget" not in cmd and cmd[cmd.index("--reasoning-format") + 1] == "deepseek"
    assert cmd[-4:] == ["--threads", "8", "--chat-template-file", r"C:\t x.jinja"]

    on = build_command("/usr/bin/llama-server", LlamaServerSettings(model_path="m.gguf", thinking="on"), "127.0.0.1", 9)
    assert on[1] == "--model"                                          # llama-server: no subcommand
    assert on[on.index("--reasoning") + 1] == "on" and on[on.index("--reasoning-budget") + 1] == "2048"


def test_endpoint_must_be_local():
    assert llamacpp_server.endpoint("http://localhost:8080/v1") == ("127.0.0.1", 8080)
    assert llamacpp_server.endpoint("http://127.0.0.1:9000") == ("127.0.0.1", 9000)
    assert llamacpp_server.endpoint("http://gpu-box:8080/v1") is None


def test_find_models(tmp_path, monkeypatch):
    hub = tmp_path / "hub"
    snap = hub / "models--Org--Coder-GGUF" / "snapshots" / "abc"
    snap.mkdir(parents=True)
    for name in ("coder-q4_k_m.gguf", "mmproj-coder-f16.gguf", "big-00001-of-00002.gguf", "big-00002-of-00002.gguf"):
        (snap / name).write_bytes(b"GGUF")
    extra = tmp_path / "my models" / "family"
    extra.mkdir(parents=True)
    (extra / "other.gguf").write_bytes(b"GGUF")
    monkeypatch.setenv("HF_HUB_CACHE", str(hub))
    monkeypatch.setenv("LLAMA_CACHE", str(tmp_path / "none"))
    monkeypatch.setattr(llamacpp_server.Path, "home", lambda: tmp_path / "home")

    models = find_models(LlamaServerSettings(model_dirs=[str(tmp_path / "my models")]))
    assert {(m["repo"], m["name"]) for m in models} == {
        ("Org/Coder-GGUF", "coder-q4_k_m.gguf"), ("Org/Coder-GGUF", "big-00001-of-00002.gguf"),
        ("family", "other.gguf")}


def test_problems_reported_before_launch(fake):
    s, _ = fake
    server = LlamaServer()
    missing = s.with_overrides({"llamacpp_server": {"model_path": "C:/nope/x.gguf"}})
    assert "model file not found" in server.status(missing)["problem"]
    with pytest.raises(LlamaServerError, match="model file not found"):
        server.start(missing, missing.path("log.txt"))
    assert "not found" in server.status(s.with_overrides({"llamacpp_server": {"executable": "no-such-llama"}}))["problem"]
    remote = s.with_overrides({"llm": {"llamacpp": {"base_url": "http://gpu-box:8080/v1"}}})
    assert "isn't on this machine" in server.status(remote)["problem"]


def test_lifecycle(fake):
    s, _ = fake
    server = LlamaServer()
    st = server.status(s)
    assert st["state"] == "stopped" and st["can_start"] and st["model_exists"]

    log = llamacpp_server.log_path_for(s)
    assert server.launch_if_needed(s, log) is True
    try:
        assert server.status(s)["state"] in ("loading", "ready") and server.status(s)["pid"]
        assert server.launch_if_needed(s, log) is False                # already up
        server.wait_ready(s, poll=0.1)
        st = server.status(s)
        assert st["state"] == "ready" and st["ready"] and not st["stale"]
        assert "server listening" in st["log_tail"] and st["command"]
        with pytest.raises(LlamaServerError, match="already listening"):
            LlamaServer().start(s, log)                                # a second launcher sees the port taken
        assert LlamaServer().status(s)["state"] == "external"
    finally:
        assert server.stop() is True
    st = server.status(s)
    assert st["state"] == "exited" and not st["ready"] and st["can_start"]
    assert server.stop() is False


def test_server_that_dies_while_loading(fake):
    s, behave = fake
    behave(exit=3)
    server = LlamaServer()
    server.start(s, llamacpp_server.log_path_for(s))
    with pytest.raises(LlamaServerError, match="stopped with code 3") as exc:
        server.wait_ready(s, poll=0.1)
    assert "failed to load model" in str(exc.value)


def test_auto_start_off(fake):
    s, _ = fake
    off = s.with_overrides({"llamacpp_server": {"auto_start": False}})
    server = LlamaServer()
    assert "start it on the Local model page" in server.run_problem(off)
    with pytest.raises(LlamaServerError):
        server.launch_if_needed(off, llamacpp_server.log_path_for(off))
    assert server.run_problem(s) == ""


def test_api(fake, tmp_path, monkeypatch):
    s, _ = fake
    settings_file = tmp_path / "settings.json"
    settings_mod.save(s, settings_file)
    server = LlamaServer()
    jobs = JobManager(tmp_path / "ws" / "_jobs", pipeline_factory=lambda job, st: None,
                      defaults_loader=lambda: settings_mod.load(settings_file), llama=server)
    client = TestClient(create_app(jobs=jobs, settings_file=settings_file))
    monkeypatch.setattr("api.app._reachable", lambda url, timeout=0.8: False)

    llama = next(p for p in client.get("/api/providers").json()["providers"] if p["name"] == "llamacpp")
    assert llama["usable"] and llama["auto_start"] and llama["model"] == "tiny.gguf"

    assert client.get("/api/llamacpp").json()["state"] == "stopped"
    assert isinstance(client.get("/api/llamacpp/models").json()["models"], list)
    try:
        st = client.post("/api/llamacpp/start").json()
        assert st["state"] in ("loading", "ready")
        deadline = time.time() + 20
        while not client.get("/api/llamacpp").json()["ready"]:
            assert time.time() < deadline
            time.sleep(0.1)
    finally:
        assert client.post("/api/llamacpp/stop").json()["state"] == "exited"

    # Without auto-start, a run on llama.cpp is refused up front while no server is up.
    client.patch("/api/settings", json={"llamacpp_server": {"auto_start": False}})
    binary = tmp_path / "Chess.exe"
    binary.write_bytes(b"MZ")
    r = client.post("/api/jobs", json={"binary": str(binary)})
    assert r.status_code == 400 and "Local model page" in r.json()["detail"]
    bad = client.patch("/api/settings", json={"llm": {"llamacpp": {"base_url": "http://gpu-box:1/v1"}},
                                              "llamacpp_server": {"auto_start": True}})
    assert bad.status_code == 200
    assert client.post("/api/llamacpp/start").status_code == 400
