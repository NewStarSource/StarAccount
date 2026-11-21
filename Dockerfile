# Runtime image for the star account service.
# The linux/amd64 binary is built by CI (or locally) into dist/staraccount first.
FROM gcr.io/distroless/static-debian12:nonroot
ARG COMMIT=unknown
LABEL org.opencontainers.image.title="staraccount" \
      org.opencontainers.image.source="https://github.com/NewStarSource/StarAccount" \
      org.opencontainers.image.revision="${COMMIT}"
COPY dist/staraccount /usr/local/bin/staraccount
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/staraccount"]
CMD ["-config", "/data/conf/account.json"]
