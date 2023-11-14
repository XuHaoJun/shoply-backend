#!/bin/sh
mkdir -p proto_out
protoc --js_out=import_style=commonjs,binary:proto_out -I ./api/proto --grpc-web_out=import_style=typescript,mode=grpcwebtext:proto_out api/proto/*.proto