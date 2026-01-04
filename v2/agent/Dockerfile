# Start with a standard base image
FROM ubuntu:22.04

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# 1. Install dependencies for eBPF compilation (BCC) and tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3 \
    python3-pip \
    python3-psutil \
    python3-matplotlib \
    python3-pandas \
    python3-seaborn \
    clang \
    llvm \
    libbpf-dev \
    linux-tools-common \
    linux-tools-generic \
    iproute2 \
    linux-headers-generic \
    iperf3 \
    iputils-ping \
    curl \
    tcpdump \
    sysstat \
    && rm -rf /var/lib/apt/lists/*

# Fix bpftool: Ubuntu installs it as a wrapper that checks uname -r (fails on Docker Desktop).
# We force symlink the installed binary to /usr/bin/bpftool AND /usr/sbin/bpftool to override the wrapper.
RUN rm -f /usr/sbin/bpftool /usr/bin/bpftool && \
    ln -sf $(find /usr/lib/linux-tools -name bpftool | head -n 1) /usr/bin/bpftool && \
    ln -sf /usr/bin/bpftool /usr/sbin/bpftool

# 2. Set up the working directory
# 2. Set up the working directory
WORKDIR /app

# 3. Install Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip3 install -r /app/requirements.txt

# 4. Copy source code (includes start.sh, agent.py, controller.py, traffic.bpf.c)
COPY src /app/src
RUN chmod +x /app/src/start.sh

# 5. Compile the eBPF program (CO-RE / Libbpf style)
# We use generic headers. This works for basic types.
RUN clang -g -O2 -target bpf -I/usr/include/$(uname -m)-linux-gnu -c /app/src/traffic.bpf.c -o /app/src/traffic.bpf.o

# Default command: Run the startup script (which loads BPF) and then the controller
CMD ["/app/src/start.sh"]