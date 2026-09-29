"""Print runtime dependencies that a plain CI runner can install."""
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

# GPU/compiled wheels — gigabytes, and the dashboard imports none of them
HEAVY = {"torch", "transformers", "accelerate", "bitsandbytes",
         "llama-cpp-python"}

deps = tomllib.load(open("pyproject.toml", "rb"))["project"]["dependencies"]
for spec in deps:
    name = spec.split(">=")[0].split("==")[0].split("[")[0].strip()
    if name.lower() not in HEAVY:
        print(spec)
