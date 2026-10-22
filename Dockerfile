FROM golang:1.27.3-bookworm AS source

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY Makefile ./
COPY api ./api
COPY cmd ./cmd
COPY internal ./internal
COPY tests ./tests
COPY migrations ./migrations
RUN make check-generated

FROM source AS test
CMD ["go", "test", "-race", "-count=1", "./..."]

FROM source AS build
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/migrate ./cmd/migrate

FROM scratch AS runtime
COPY --from=build /out/server /server
COPY --from=build /out/migrate /migrate
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65532:65532
ENV HTTP_ADDR=:8443
EXPOSE 8443
ENTRYPOINT ["/server"]
