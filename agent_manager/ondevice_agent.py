"""
ondevice_agent.py — local LLM via HuggingFace transformers or llama-cpp-python.
Auto-detects GGUF models and uses the correct loader.
"""

import re
import sys
import glob
import os
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig


def _estimate_gflops(n_params: int | None, prompt_tokens, completion_tokens) -> float | None:
    """
    Kaplan et al. (2020) approximation: FLOPs = 2 * N * T, N = non-embedding
    params, T = total tokens processed (prompt + generated). Same formula
    the old evaluation/computation_cost.py used, generalized to any model —
    n_params is read from whatever model is actually loaded, never hardcoded
    to one architecture's known size.
    """
    if not n_params or not prompt_tokens or not completion_tokens:
        return None
    total_tokens = prompt_tokens + completion_tokens
    return round(2 * n_params * total_tokens / 1e9, 4)


def _is_gguf(model_id: str) -> bool:
    return "gguf" in model_id.lower()


def _list_gguf_files(model_id: str) -> list[str]:
    """List every .gguf file cached for this HuggingFace repo (full paths)."""
    folder  = "models--" + model_id.replace("/", "--")
    cache   = os.path.expanduser("~/.cache/huggingface/hub/")
    pattern = os.path.join(cache, folder, "**", "*.gguf")
    return glob.glob(pattern, recursive=True)


def _find_gguf_file(model_id: str, preferred_file: str = "") -> str | None:
    """
    Find the .gguf file to load for this model. If multiple quant variants
    are cached for the same repo (e.g. downloaded at different times via
    `hp init`), `preferred_file` (the basename picked/recorded in
    config.yaml's agents.on_device.gguf_file) disambiguates which one to
    load instead of silently taking whichever glob() lists first.
    """
    files = _list_gguf_files(model_id)
    if not files:
        return None

    if preferred_file:
        for f in files:
            if os.path.basename(f) == preferred_file:
                return f
        for f in files:
            if preferred_file in os.path.basename(f):
                return f
        print(f"[on_device] WARNING: configured gguf_file {preferred_file!r} not found "
              f"among cached files for {model_id} — falling back to first match.")

    return files[0]


class OnDeviceAgent:
    def __init__(self, model: str, quantization: str = "4bit",
                 temperature: float = 0.7, max_tokens: int = 256,
                 do_sample: bool = True, gguf_file: str = ""):
        self.model_name  = model
        self.temperature = temperature
        self.max_tokens  = max_tokens
        self.do_sample   = do_sample
        self.is_gguf     = _is_gguf(model)
        self.gguf_file   = gguf_file

        print(f"[on_device] Loading {model} ({quantization})...")

        if self.is_gguf:
            self._load_gguf(model)
        else:
            self._load_transformers(model, quantization)

        print(f"[on_device] Ready.")

    def _load_gguf(self, model: str):
        """Load a GGUF model using llama-cpp-python."""
        try:
            import llama_cpp
            from llama_cpp import Llama
        except ImportError:
            print("\n[on_device] ✗ llama-cpp-python not installed.")
            print("  Run: CMAKE_ARGS=\"-DGGML_CUDA=on\" pip install llama-cpp-python")
            sys.exit(1)

        gguf_path = _find_gguf_file(model, self.gguf_file)
        if not gguf_path:
            print(f"\n[on_device] ✗ No .gguf file found for {model}")
            print("  Try re-downloading the model via `hp init`.")
            sys.exit(1)

        print(f"[on_device] GGUF file: {os.path.basename(gguf_path)}")
        try:
            self.llm = Llama(
                model_path=gguf_path,
                n_gpu_layers=-1,
                n_ctx=8192,      # ← increase this, still fits in 8GB VRAM
                verbose=False,
                seed=0,          # fixed seed for reproducibility — removes
                                 # one source of run-to-run variation, but
                                 # NOT sufficient alone at temperature=0
                                 # (greedy decoding doesn't sample, so seed
                                 # doesn't touch the real cause: GPU
                                 # floating-point reduction order isn't
                                 # bit-exact across runs). True determinism
                                 # would need n_gpu_layers=0 (CPU-only),
                                 # which trades away most of the speed this
                                 # agent exists for.
            )
            self.model     = None
            self.tokenizer = None
            # read directly from the loaded model's own metadata — works for
            # whatever GGUF is actually loaded, not tied to one architecture
            try:
                self.n_params = llama_cpp.llama_model_n_params(self.llm._model.model)
            except Exception:
                self.n_params = None
        except Exception as e:
            print(f"\n[on_device] ✗ Failed to load GGUF model: {e}")
            sys.exit(1)

    def _load_transformers(self, model: str, quantization: str):
        """Load a standard HuggingFace model using transformers."""
        load_kwargs = {"device_map": "auto"}
        if quantization == "4bit":
            load_kwargs["quantization_config"] = BitsAndBytesConfig(load_in_4bit=True)
        elif quantization == "8bit":
            load_kwargs["quantization_config"] = BitsAndBytesConfig(load_in_8bit=True)

        try:
            self.model     = AutoModelForCausalLM.from_pretrained(model, **load_kwargs)
            self.tokenizer = AutoTokenizer.from_pretrained(model)
            self.llm       = None
            self.n_params  = sum(
                p.numel() for name, p in self.model.named_parameters()
                if "embed" not in name
            )
        except ValueError as e:
            print(f"\n[on_device] ✗ Not enough VRAM for {quantization}.")
            print(f"  → Try 4bit or a smaller model.")
            print(f"  → Detail: {e}")
            sys.exit(1)
        except RuntimeError as e:
            if "out of memory" in str(e).lower():
                print(f"\n[on_device] ✗ GPU out of memory.")
                print(f"  → Try 4bit or a smaller model.")
            else:
                print(f"\n[on_device] ✗ Runtime error: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"\n[on_device] ✗ Unexpected error: {e}")
            sys.exit(1)

    def send(self, system_prompt: str, user_prompt: str) -> str:
        text, _ = self._generate(system_prompt, user_prompt)
        return text

    def send_with_usage(self, system_prompt: str, user_prompt: str):
        """Same as send(), but also returns token usage.

        Returns (text: str, usage: dict | None), usage = {"prompt_tokens",
        "completion_tokens", "total_tokens"}. No "cost" key — on_device has
        no per-token billing, unlike CloudAgent.send_with_usage().
        """
        return self._generate(system_prompt, user_prompt)

    # Coarse pre-check ceiling — deliberately generous (real system_prompt is
    # already ~12,000 chars before SRi/Hi; a long session's accumulated
    # context can reasonably reach several times that). Only exists to keep
    # truly pathological input (confirmed: 73,412 chars) away from ANY
    # llama.cpp call, including tokenize() itself — see below.
    _MAX_PROMPT_CHARS_HARD_CEILING = 40_000

    def _generate(self, system_prompt: str, user_prompt: str):
        # A real attacker can trivially paste/send an extremely long garbage
        # string — confirmed: a 73KB repeated "PuTTYPuTTY..." terminal-title
        # artifact (from a real historical session in the dataset) crashed
        # llama.cpp at the C++ level outright. That's a real segfault, not a
        # Python exception, so the try/except below never even runs — the
        # whole process dies instantly, taking down every connected
        # attacker's session with it, not just this one. Must be checked
        # BEFORE ever reaching the model, in production as well as eval.
        #
        # Two stages, because ONE check turned out not to be enough:
        #  1. A cheap character-count pre-check FIRST, generous enough to
        #     never trip on a normal (even long-session) prompt. This has
        #     to run before calling ANY llama.cpp function — tokenize()
        #     itself segfaulted on the 73KB string in testing, so "just
        #     tokenize first and check the count" isn't safe on its own.
        #  2. Only once that coarse check passes do we tokenize for the
        #     PRECISE check against n_ctx — a flat char-count ceiling alone
        #     was tried first and badly miscalibrated (6000 chars, when the
        #     real base_prompt+system_setting is already ~12,000 chars
        #     before SRi/Hi/command content — silently blocked 87% of all
        #     real calls in one run before this was caught).
        combined_text = system_prompt + user_prompt
        if len(combined_text) > self._MAX_PROMPT_CHARS_HARD_CEILING:
            return "", None

        if self.is_gguf and self.llm is not None:
            try:
                n_tokens = len(self.llm.tokenize(combined_text.encode("utf-8", errors="ignore")))
                n_ctx    = self.llm.n_ctx()
                if n_tokens > n_ctx - self.max_tokens - 64:   # small safety margin
                    return "", None
            except Exception:
                pass   # tokenization itself failing shouldn't block a real attempt
        try:
            if self.is_gguf:
                return self._send_gguf(system_prompt, user_prompt)
            else:
                return self._send_transformers(system_prompt, user_prompt)
        except Exception as e:
            return f"[on_device error: {e}]", None

    def _send_gguf(self, system_prompt: str, user_prompt: str):
        output = self.llm.create_chat_completion(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            repeat_penalty=1.15,
        )
        response = output["choices"][0]["message"]["content"].strip()
        response = re.sub(r'```\w*\n?', '', response).strip()
        usage_data = output.get("usage") or {}
        usage = {
            "prompt_tokens":     usage_data.get("prompt_tokens"),
            "completion_tokens": usage_data.get("completion_tokens"),
            "total_tokens":      usage_data.get("total_tokens"),
            "gflops":            _estimate_gflops(
                self.n_params,
                usage_data.get("prompt_tokens"),
                usage_data.get("completion_tokens"),
            ),
        } if usage_data else None
        return response, usage

    def _send_transformers(self, system_prompt: str, user_prompt: str):
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ]
        text = self.tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True,
        )
        model_inputs = self.tokenizer([text], return_tensors="pt").to(self.model.device)
        generated_ids = self.model.generate(
            **model_inputs,
            max_new_tokens=self.max_tokens,
            temperature=self.temperature,
            do_sample=self.do_sample,
            repetition_penalty=1.15,
        )
        prompt_tokens = model_inputs.input_ids.shape[1]
        generated_ids = [
            out[len(inp):]
            for inp, out in zip(model_inputs.input_ids, generated_ids)
        ]
        completion_tokens = generated_ids[0].shape[0]
        response = self.tokenizer.batch_decode(
            generated_ids, skip_special_tokens=True
        )[0].strip()
        response = re.sub(r'```\w*\n?', '', response).strip()

        user_cmd = user_prompt.strip().splitlines()[-1].strip()
        lines    = response.splitlines()
        if lines and user_cmd in lines[0]:
            response = "\n".join(lines[1:]).strip()

        usage = {
            "prompt_tokens":     int(prompt_tokens),
            "completion_tokens": int(completion_tokens),
            "total_tokens":      int(prompt_tokens + completion_tokens),
            "gflops":            _estimate_gflops(self.n_params, int(prompt_tokens), int(completion_tokens)),
        }
        return response, usage