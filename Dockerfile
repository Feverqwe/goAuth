ARG BASE_IMAGE=alpine:3.21
ARG GOLANG_IMAGE=golang:1.23-alpine3.21

FROM $GOLANG_IMAGE AS build
LABEL stage=build
WORKDIR /build
RUN apk add musl-dev
ADD . .
RUN go build -o goAuth

FROM $BASE_IMAGE AS release

RUN apk upgrade

COPY --from=build /build/goAuth /opt/goAuth

EXPOSE 81

ENV PROFILE_PLACE=/config
CMD /opt/goAuth
