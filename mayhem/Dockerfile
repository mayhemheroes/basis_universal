FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake clang

COPY . /repo
WORKDIR /repo/build
RUN cmake ..
RUN make -j8
RUN clang++ /repo/mayhem/fuzz_floor_log2i.cpp -fsanitize=fuzzer,address -I /repo/transcoder/ -o /fuzz

FROM ubuntu:22.04 as package
COPY --from=builder /fuzz /fuzz_floor_log2i
