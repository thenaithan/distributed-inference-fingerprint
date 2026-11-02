"""Send streaming chat completions to an OpenAI-compatible endpoint, one after another,
and log when each request started, got its first token and ended (host clock, same as the
pcap). Works against exo (52415), llama-server (8080) and LocalAI (8080).

    python3 capture/requests.py --base http://localhost:8080 --model <id> --n 20 --max-tokens 30
    python3 capture/requests.py ... --prompt-tokens 2048 --n 5        # long prefill
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.request

PROMPT = "Explain, in plain words and without lists, why a pipeline-parallel inference system loses the whole request when one stage disappears."
FILLER = "The quick brown fox jumps over the lazy dog. "      # ~10 tokens per repetition


def one(base: str, model: str, prompt: str, max_tokens: int, thinking: bool, timeout: float) -> dict:
    body = {"model": model, "stream": True, "max_tokens": max_tokens, "temperature": 0,
            "messages": [{"role": "user", "content": prompt}]}
    if not thinking:
        body["enable_thinking"] = False                 # exo honours this; others ignore it
        body["chat_template_kwargs"] = {"enable_thinking": False}   # llama-server / LocalAI
    req = urllib.request.Request(base + "/v1/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    t_req, t_first, n = time.time(), None, 0
    t_last = t_req
    stream_error, finish = None, None
    timings = None
    with urllib.request.urlopen(req, timeout=timeout) as r:
        for raw in r:
            # the socket timeout only fires when no bytes arrive; llama-server keeps a stalled
            # stream alive with a small send every ~25 s, so the deadline is counted from the
            # last token, not the last byte
            if time.time() - t_last > timeout:
                raise TimeoutError(f"no token for {timeout:.0f} s ({n} received)")
            if not raw.startswith(b"data:"):
                continue
            p = raw[5:].strip()
            if p == b"[DONE]":
                break
            try:
                obj = json.loads(p)
            except json.JSONDecodeError:
                continue
            if obj.get("timings"):                 # llama-server: server-side timings in the last chunk
                timings = obj["timings"]
            # a failure after the first chunk comes in-band, after HTTP 200: an {"error": ...}
            # event then [DONE] (LocalAI v4.12.1 chat.go; read 2026-11-02, after this script had
            # been skipping it as a chunk without choices)
            if obj.get("error"):
                stream_error = obj["error"]
            choice = (obj.get("choices") or [{}])[0]
            if choice.get("finish_reason"):
                finish = choice["finish_reason"]
            ch = choice.get("delta", {})
            # thinking tokens: reasoning_content (llama-server), reasoning (LocalAI v4)
            if ch.get("content") or ch.get("reasoning_content") or ch.get("reasoning"):
                n += 1
                t_last = time.time()
                if t_first is None:
                    t_first = t_last
    return dict(t_request=t_req, t_first_token=t_first, t_end=time.time(), tokens=n, timings=timings,
                finish_reason=finish, stream_error=stream_error)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8080")
    ap.add_argument("--model", default="")
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--max-tokens", type=int, default=30)
    ap.add_argument("--prompt", default=PROMPT, help="the user message; exo at CPU speed needs a short one, its runner is killed after 90 s without a token")
    ap.add_argument("--prompt-tokens", type=int, default=0, help="pad the prompt to about this many tokens")
    ap.add_argument("--gap", type=float, default=5.0, help="seconds between requests")
    ap.add_argument("--thinking", action="store_true")
    ap.add_argument("--timeout", type=float, default=900.0)
    ap.add_argument("--out", default="requests.jsonl")
    ap.add_argument("--same-prompt", action="store_true",
                    help="send the identical prompt every time (llama-server's prompt cache then serves "
                         "the prefill from RAM after the first request; by default a per-request prefix defeats it)")
    a = ap.parse_args()
    with open(a.out, "a") as fh:
        for i in range(a.n):
            prompt = a.prompt if a.same_prompt else f"Request {i} of {a.n}. " + a.prompt
            if a.prompt_tokens:
                prompt = ("" if a.same_prompt else f"Request {i}. ") + FILLER * max(1, a.prompt_tokens // 10) + a.prompt
            # t_request before the call, so a request that fails (a pause timeout) keeps it;
            # one() overwrites it with its own, a few microseconds later
            rec = dict(i=i, base=a.base, prompt_tokens_requested=a.prompt_tokens, max_tokens=a.max_tokens,
                       same_prompt=a.same_prompt, t_request=time.time())
            try:
                rec.update(one(a.base, a.model, prompt, a.max_tokens, a.thinking, a.timeout))
            except Exception as e:                      # noqa: BLE001
                rec.update(error=repr(e), t_end=time.time())
            fh.write(json.dumps(rec) + "\n"); fh.flush()
            ft = rec.get("t_first_token")
            print(f"{i}: {rec.get('tokens', 0)} tokens, first token after "
                  f"{(ft - rec['t_request']) if ft else float('nan'):.2f} s, total {rec['t_end'] - rec['t_request']:.1f} s"
                  + (f"  {rec['error']}" if "error" in rec else "")
                  + (f"  stream error: {rec['stream_error']}" if rec.get("stream_error") else ""))
            time.sleep(a.gap)


if __name__ == "__main__":
    main()
