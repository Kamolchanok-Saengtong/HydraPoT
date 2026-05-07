"""
ondevice_agent.py — local LLM via HuggingFace transformers.
Reads model/quant/temperature from config (passed in by main.py).
"""

import re
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig


class OnDeviceAgent:
    def __init__(self, model: str, quantization: str = "4bit",
                 temperature: float = 0.7, max_tokens: int = 256,
                 do_sample: bool = True):
        # store generation params for use in send()
        self.model_name  = model
        self.temperature = temperature
        self.max_tokens  = max_tokens
        self.do_sample   = do_sample

        # build quantization config from the user's choice
        load_kwargs = {"device_map": "auto"}
        if quantization == "4bit":
            load_kwargs["quantization_config"] = BitsAndBytesConfig(load_in_4bit=True)
        elif quantization == "8bit":
            load_kwargs["quantization_config"] = BitsAndBytesConfig(load_in_8bit=True)
        # "none" → full precision, no quant config

        print(f"[on_device] Loading {model} ({quantization})...")
        self.model     = AutoModelForCausalLM.from_pretrained(model, **load_kwargs)
        self.tokenizer = AutoTokenizer.from_pretrained(model)
        print(f"[on_device] Ready.")

    def send(self, system_prompt: str, user_prompt: str) -> str:
        try:
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
                max_new_tokens=self.max_tokens,     # ← from config
                temperature=self.temperature,       # ← from config
                do_sample=self.do_sample,           # ← from config
            )

            generated_ids = [
                out[len(inp):]
                for inp, out in zip(model_inputs.input_ids, generated_ids)
            ]

            response = self.tokenizer.batch_decode(
                generated_ids, skip_special_tokens=True
            )[0].strip()

            response = re.sub(r'```\w*\n?', '', response).strip()

            user_cmd = user_prompt.strip().splitlines()[-1].strip()
            lines    = response.splitlines()
            if lines and user_cmd in lines[0]:
                response = "\n".join(lines[1:]).strip()

            return response

        except Exception as e:
            return f"[on_device error: {e}]"