FROM golang:1.27.0-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/bearly-secure ./cmd/server
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/bearly-attacker-lab ./cmd/attackerlab

FROM alpine:3.22

RUN apk add --no-cache ca-certificates && addgroup -S bearly && adduser -S -G bearly bearly
WORKDIR /app
COPY --from=build --chown=bearly:bearly /out/bearly-secure ./bearly-secure
COPY --from=build --chown=bearly:bearly /out/bearly-attacker-lab ./bearly-attacker-lab
COPY --chown=bearly:bearly attacker-lab ./attacker-lab
COPY --chown=bearly:bearly data/uploads/mystery-shack-tax-exemption.pdf ./data/uploads/mystery-shack-tax-exemption.pdf
COPY --chown=bearly:bearly web ./web
RUN chown bearly:bearly ./data

USER bearly
EXPOSE 3030 4040
CMD ["./bearly-secure"]
