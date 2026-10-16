"""Local stand-in for api.minimoth.dev, shaped after https://minimoth.dev/llms-full.txt (tests only)."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY, GOOD_CODE = "mm_test_fake", "123456"


class State:
    sent, tokens, logged_out, fail_send = [], {}, [], None


def make_handler(state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def _send(self, status, obj):
            b = json.dumps(obj).encode()
            self.send_response(status); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

        def _err(self, status, code): self._send(status, {"error": code.title(), "code": code, "request_id": "req_t"})

        def do_POST(self):
            if "X-Api-Key" not in self.headers: return self._err(401, "MISSING_API_KEY")
            if self.headers["X-Api-Key"] != KEY: return self._err(401, "INVALID_API_KEY")
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            p = self.path
            if p == "/v1/otp/send":
                if state.fail_send: return self._err(*state.fail_send)
                if not str(body.get("phone", "")).startswith("+91"): return self._err(422, "INVALID_PHONE")
                state.sent.append(body["phone"]); return self._send(200, {"otp_id": "otp_1", "expires_at": "2099-01-01T00:00:00Z"})
            if p == "/v1/otp/verify":
                code = str(body.get("code", ""))
                if len(code) != 6 or not code.isdigit(): return self._err(422, "INVALID_OTP_CODE")
                if body.get("phone") not in state.sent: return self._err(400, "OTP_NOT_FOUND")
                if code != GOOD_CODE: return self._err(400, "INVALID_OTP")
                state.tokens = {"access_token": "acc_1", "refresh_token": "ref_1", "expires_at": "2099-01-01T00:00:00Z"}
                return self._send(200, {**state.tokens, "identity_id": "id_1"})
            if p == "/v1/session/validate":
                return self._send(200, {"valid": body.get("access_token") == state.tokens.get("access_token")})
            if p == "/v1/session/refresh":
                if body.get("refresh_token") != state.tokens.get("refresh_token"): return self._err(401, "SESSION_EXPIRED")
                state.tokens = {"access_token": "acc_2", "refresh_token": "ref_2", "expires_at": "2099-01-01T00:00:00Z"}
                return self._send(200, state.tokens)
            if p == "/v1/session/logout":
                state.logged_out.append(body.get("access_token")); state.tokens = {}; return self._send(200, {})
            self._err(404, "NOT_FOUND")
    return H


def start():
    st = State(); st.sent, st.tokens, st.logged_out, st.fail_send = [], {}, [], None
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(st))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, st, f"http://127.0.0.1:{srv.server_address[1]}"
