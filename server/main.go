package main

import (
	"fmt"
	"log"
	"net"
	"os"

	secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/jewertow/trust-bundle-sds/server/sds"
	"google.golang.org/grpc"
)

func main() {
	trustBundle := os.Getenv("TRUST_BUNDLE")
	if trustBundle == "" {
		log.Fatalf("failed to find TRUST_BUNDLE environment variable")
	}
	fmt.Printf("Trust bundle:\n%s\n", trustBundle)

	fmt.Println("Starting SDS server")
	lis, err := net.Listen("tcp", "0.0.0.0:15012")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	handler := sds.Handler{TrustBundlePEM: trustBundle}
	secret_v3.RegisterSecretDiscoveryServiceServer(s, &handler)

	err = s.Serve(lis)
	if err != nil {
		log.Fatalf("failed to serve gRPC: %v", err)
	}
}
