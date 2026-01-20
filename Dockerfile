FROM alpine:latest

# 安装必要依赖
RUN apk add --no-cache ca-certificates libc6-compat libgcc libstdc++ curl unzip

WORKDIR /app

ARG TARGETARCH
ARG VERSION

RUN set -ex; \
    # 根据架构匹配文件名
    if [ "$TARGETARCH" = "amd64" ]; then \
        FILE_NAME="x86_64-unknown-linux-musl.zip"; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
        FILE_NAME="aarch64-unknown-linux-musl.zip"; \
    fi; \
    \
    URL="https://github.com/yujincheng08/rust-iptv-proxy/releases/download/${VERSION}/${FILE_NAME}"; \
    echo "Downloading: ${URL}"; \
    \
    # 下载并解压
    curl -L -f -o "package.zip" "${URL}" && \
    unzip "package.zip" && \
    rm "package.zip"; \
    \
    # 移动解压出的 iptv 文件到当前目录
    mv $(find . -type f -name "iptv" -print -quit) ./iptv && \
    chmod +x iptv

# 暴露端口
EXPOSE 7878

# 程序启动
ENTRYPOINT ["./iptv", "--bind", "0.0.0.0:7878"]

# 默认运行参数
CMD ["--help"]
