package sds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"

	core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

var _ secret_v3.SecretDiscoveryServiceServer = &Handler{}

type Handler struct {
	TrustBundlePEM string
}

func (h *Handler) DeltaSecrets(secret_v3.SecretDiscoveryService_DeltaSecretsServer) error {
	return status.Error(codes.Unimplemented, "DeltaSecrets is not implemented")
}

func (h *Handler) StreamSecrets(stream secret_v3.SecretDiscoveryService_StreamSecretsServer) error {
	reqch := make(chan *discovery_v3.DiscoveryRequest, 1)
	errch := make(chan error, 1)

	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				if status.Code(err) == codes.Canceled || errors.Is(err, io.EOF) {
					err = nil
				}
				errch <- err
				return
			}
			reqch <- req
		}
	}()

	var versionCounter int64
	var versionInfo = strconv.FormatInt(versionCounter, 10)
	var lastNonce string
	var lastNode *core_v3.Node
	var lastReq *discovery_v3.DiscoveryRequest
	for {
		select {
		case newReq := <-reqch:
			log.Printf("StreamSecrets: Received a request [%v, %s, %s]", newReq.ResourceNames, newReq.VersionInfo, newReq.ResponseNonce)

			if newReq.ErrorDetail != nil {
				log.Printf("StreamSecrets: Envoy reported errors: [%v, %s]", newReq.ResourceNames, newReq.ErrorDetail.Message)
			}

			// If we've previously sent a nonce, this must be a reply
			if lastNonce != "" {
				// The nonce should match the last sent nonce, otherwise
				// it's stale and the request should be ignored.
				if lastNonce != newReq.ResponseNonce {
					log.Printf("StreamSecrets: Received unexpected nonce; ignoring request: [%s, %s]", newReq.ResponseNonce, lastNonce)
					continue
				}

				if newReq.VersionInfo == "" || newReq.VersionInfo != versionInfo {
					// The caller has failed to apply the last update.
					// A NACK might also contain an update to the resource hint, so we need to continue processing.
					log.Printf("StreamSecrets: Received unexpected nonce; ignoring request: [%s, %s]", newReq.ResponseNonce, lastNonce)
				}
				// If the current request does not contain node information, use the information from a previous request (if any)
				if newReq.Node == nil {
					newReq.Node = lastNode
				}
			}

			var sendUpdates = lastReq == nil

			// save request so that all future workload updates lead to SDS updates for the last request
			lastReq = newReq

			if !sendUpdates {
				continue
			}

		case err := <-errch:
			log.Printf("StreamSecrets: Received error from stream secrets server: %s", err)
			return err
		}

		if len(lastReq.ResourceNames) > 1 {
			return fmt.Errorf("workload is not allowed to request more than 1 secret")
		}
		if lastReq.ResourceNames[0] != "ROOTCA" {
			return fmt.Errorf("workload is not allowed to request secrets other than ROOTCA")
		}
		validationContext, err := anypb.New(&tls_v3.Secret{
			Name: lastReq.ResourceNames[0],
			Type: &tls_v3.Secret_ValidationContext{
				ValidationContext: &tls_v3.CertificateValidationContext{
					TrustedCa: &core_v3.DataSource{
						Specifier: &core_v3.DataSource_InlineBytes{
							InlineBytes: []byte(h.TrustBundlePEM),
						},
					},
				},
			},
		})
		if err != nil {
			log.Printf("failed to serialize secret ROOTCA: %s", err)
			return err
		}
		resp := &discovery_v3.DiscoveryResponse{
			TypeUrl:     lastReq.TypeUrl,
			VersionInfo: versionInfo,
		}
		resp.Resources = append(resp.Resources, validationContext)

		log.Printf("StreamSecrets: Sending response: [%s, %s, %v]", resp.VersionInfo, resp.Nonce, resp.Resources)
		if err := stream.Send(resp); err != nil {
			log.Printf("StreamSecrets: error sending secrets over stream: %s", err)
			return err
		}

		// remember the last nonce
		lastNonce = resp.Nonce

		// Remember Node info if it exists
		if lastReq.Node != nil {
			lastNode = lastReq.Node
		}
	}
}

func (h *Handler) FetchSecrets(ctx context.Context, req *discovery_v3.DiscoveryRequest) (*discovery_v3.DiscoveryResponse, error) {
	return nil, status.Error(codes.Unimplemented, "FetchSecrets is not implemented")
}
