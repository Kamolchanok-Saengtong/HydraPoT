from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
import re

MODEL_NAME = "Qwen/Qwen2.5-Coder-7B-Instruct"

class OnDeviceAgent:
    def __init__(self):
        bnb_config = BitsAndBytesConfig(load_in_4bit=True)

        self.model = AutoModelForCausalLM.from_pretrained(
            MODEL_NAME,
            quantization_config=bnb_config,
            device_map="auto",
        )
        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    def send(self, system_prompt: str, user_prompt: str) -> str:
        try:
            messages = [                                      # ← fixed indent (was 1 level too deep)
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ]

            text = self.tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )

            model_inputs = self.tokenizer([text], return_tensors="pt").to(self.model.device)

            generated_ids = self.model.generate(
                **model_inputs,
                max_new_tokens=256,
                temperature=0.7,
                do_sample=True,
            )

            generated_ids = [
                out[len(inp):]
                for inp, out in zip(model_inputs.input_ids, generated_ids)
            ]

            response = self.tokenizer.batch_decode(
                generated_ids,
                skip_special_tokens=True
            )[0].strip()

            # strip markdown backticks
            response = re.sub(r'```\w*\n?', '', response).strip()

            # strip if first line echoes the command
            user_cmd = user_prompt.strip().splitlines()[-1].strip()
            lines    = response.splitlines()
            if lines and user_cmd in lines[0]:
                response = "\n".join(lines[1:]).strip()

            return response

        except Exception as e:
            return f"[on_device error: {e}]"