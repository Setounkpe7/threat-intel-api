# Tiny image used to render docs/assets/hero-demo.tape into a GIF.
# The official ghcr.io/charmbracelet/vhs image does not bundle curl or jq,
# which the tape needs to hit the live API and pretty-print JSON.
#
# Build:
#   docker build -t threat-intel-vhs -f docs/assets/hero-demo.Dockerfile docs/assets/
#
# Render (from the repo root):
#   docker run --rm --shm-size=1g --cap-add=SYS_ADMIN \
#     -v "$PWD":/vhs -w /vhs threat-intel-vhs \
#     docs/assets/hero-demo.tape
#
# Then chown the output if it landed as root:
#   docker run --rm -v "$PWD":/vhs alpine \
#     chown $(id -u):$(id -g) /vhs/docs/assets/screenshots/hero-demo.gif

FROM ghcr.io/charmbracelet/vhs

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl jq ca-certificates \
    && rm -rf /var/lib/apt/lists/*
