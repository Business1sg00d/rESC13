FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
apt-get install -y pkg-config libssl-dev libclang-dev libkrb5-dev krb5-user curl git build-essential && \
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

RUN git clone https://github.com/Business1sg00d/rESC13 /opt/rESC13 && \
cd /opt/rESC13/ && cargo build
