"""
HydraPoT Plugin — Fake Docker Output
=====================================
Drop this file into plugins/static/ to handle docker commands.

Required:
  COMMANDS = ["docker"]          — list of command bases this plugin handles
  handle(cmd, write_fn) -> str   — generates fake output
"""

COMMANDS = ["docker"]


def handle(cmd: str, write_fn) -> str:
    parts = cmd.strip().split()
    if len(parts) < 2:
        return (
            "Usage:  docker [OPTIONS] COMMAND [ARG...]\n"
            "        docker [ --help | -v | --version ]\n\n"
            "A self-sufficient runtime for containers"
        )

    sub = parts[1]

    if sub == "ps":
        show_all = "-a" in parts
        lines = [
            "CONTAINER ID   IMAGE          COMMAND       CREATED       STATUS          PORTS     NAMES"
        ]
        lines.append(
            "a1b2c3d4e5f6   nginx:latest   \"nginx -g…\"   2 weeks ago   Up 3 days       80/tcp    web_server"
        )
        lines.append(
            "f6e5d4c3b2a1   mysql:8.0      \"mysqld\"      3 weeks ago   Up 3 days       3306/tcp  db_backend"
        )
        if show_all:
            lines.append(
                "1a2b3c4d5e6f   redis:7        \"redis-se…\"   4 weeks ago   Exited (0) 2d             cache_old"
            )
        return "\n".join(lines)

    elif sub == "images":
        return (
            "REPOSITORY   TAG       IMAGE ID       CREATED        SIZE\n"
            "nginx        latest    a1b2c3d4e5f6   2 weeks ago    142MB\n"
            "mysql        8.0      f6e5d4c3b2a1   3 weeks ago    565MB\n"
            "redis        7        1a2b3c4d5e6f   4 weeks ago    130MB"
        )

    elif sub in ("stop", "kill", "rm"):
        container = parts[2] if len(parts) > 2 else ""
        return container

    elif sub == "version":
        return (
            "Client: Docker Engine - Community\n"
            " Version:           24.0.7\n"
            " API version:       1.43\n"
            " Go version:        go1.20.10\n"
            " Git commit:        afdd53b\n"
            " Built:             Thu Oct 26 09:08:17 2023\n"
            " OS/Arch:           linux/amd64\n"
            " Context:           default"
        )

    elif sub == "info":
        return (
            "Containers: 3\n"
            " Running: 2\n"
            " Paused: 0\n"
            " Stopped: 1\n"
            "Images: 3\n"
            "Server Version: 24.0.7\n"
            "Storage Driver: overlay2\n"
            "Logging Driver: json-file\n"
            "Cgroup Driver: systemd\n"
            "Kernel Version: 5.15.0-91-generic\n"
            "Operating System: Ubuntu 22.04 LTS\n"
            "OSType: linux\n"
            "Architecture: x86_64\n"
            "CPUs: 4\n"
            "Total Memory: 7.792GiB"
        )

    elif sub == "logs":
        container = parts[2] if len(parts) > 2 else "unknown"
        return (
            f"2026-05-10T14:00:00Z {container}: Starting application...\n"
            f"2026-05-10T14:00:01Z {container}: Listening on port 80\n"
            f"2026-05-10T14:00:02Z {container}: Ready to accept connections"
        )

    elif sub == "exec":
        return ""  # silent success like real docker exec

    elif sub in ("pull", "build"):
        image = parts[2] if len(parts) > 2 else "latest"
        return f"Using default tag: latest\nlatest: Pulling from library/{image}\nDigest: sha256:a1b2c3d4e5f6...\nStatus: Downloaded newer image for {image}:latest"

    else:
        return f"docker: '{sub}' is not a docker command.\nSee 'docker --help'"