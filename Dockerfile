FROM alpine:latest AS builder

# 仅在构建阶段安装下载和解压工具
RUN apk add --no-cache curl unzip

WORKDIR /app

ARG TARGETARCH
ARG VERSION

RUN set -ex; \
    if [ "$TARGETARCH" = "amd64" ]; then \
        FILE_NAME="x86_64-unknown-linux-musl.zip"; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
        FILE_NAME="aarch64-unknown-linux-musl.zip"; \
    fi; \
    \
    URL="https://github.com/yujincheng08/rust-iptv-proxy/releases/download/${VERSION}/${FILE_NAME}"; \
    \
    curl -L -f -o "package.zip" "${URL}" && \
    unzip "package.zip" && \
    # 找到二进制文件并重命名/移动到固定位置，方便下一阶段拷贝
    mv iptv /app/iptv_bin

FROM alpine:latest
# 只保留程序运行必不可少的运行时库
RUN apk add --no-cache ca-certificates libgcc libstdc++

WORKDIR /app

COPY --from=builder --chmod=755 /app/iptv_bin ./iptv

EXPOSE 7878

ENTRYPOINT ["./iptv", "--bind", "0.0.0.0:7878"]
CMD ["--help"]
