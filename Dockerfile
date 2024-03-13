FROM redhat/ubi9-minimal
COPY out/server /usr/bin/server
ENTRYPOINT ["/usr/bin/server"]
