// Copyright The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	apiVersion = "externaldata.gatekeeper.sh/v1beta1"

	gatekeeperCAFile = "/gatekeeper/ca.crt"
	cosignPubKeyFile = "/cosign/cosign.pub"
	serverCert       = "/certs/tls.crt"
	serverKey        = "/certs/tls.key"
)

func main() {
	fmt.Println("starting server...")

	gatekeeperCA, err := os.ReadFile(gatekeeperCAFile)
	if err != nil {
		fmt.Println(err, "unable to load gatekeeper ca certificate", "gatekeeperCAFile", gatekeeperCAFile)
		os.Exit(1)
	}

	gatekeeperCAs := x509.NewCertPool()
	gatekeeperCAs.AppendCertsFromPEM(gatekeeperCA)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientCAs:  gatekeeperCAs,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/validate", validate)

	server := &http.Server{
		Addr:              ":8090",
		Handler:           mux,
		ReadHeaderTimeout: time.Duration(5) * time.Second,
		TLSConfig:         tlsConfig,
	}

	if err := server.ListenAndServeTLS(serverCert, serverKey); err != nil {
		panic(err)
	}
}

func validate(w http.ResponseWriter, req *http.Request) {
	// only accept POST requests
	if req.Method != http.MethodPost {
		sendResponse(nil, "only POST is allowed", w)
		return
	}

	// read request body
	requestBody, err := io.ReadAll(req.Body)
	if err != nil {
		sendResponse(nil, fmt.Sprintf("unable to read request body: %v", err), w)
		return
	}

	// parse request body
	var providerRequest externaldata.ProviderRequest
	err = json.Unmarshal(requestBody, &providerRequest)
	if err != nil {
		sendResponse(nil, fmt.Sprintf("unable to unmarshal request body: %v", err), w)
		return
	}

	results := make([]externaldata.Item, 0)

	ctx := req.Context()
	ro := options.RegistryOptions{}
	co, err := ro.ClientOpts(ctx)
	if err != nil {
		sendResponse(nil, fmt.Sprintf("unable to create cosign registry options: %v", err), w)
		return
	}

	// rekorClient := &client.Rekor{}

	// rootCerts, err := fulcio.GetRoots()
	// if err != nil {
	// 	sendResponse(nil, fmt.Sprintf("unable to get fulcio roots: %v", err), w)
	// 	return
	// }

	// iterate over all keys
	for _, key := range providerRequest.Request.Keys {
		fmt.Println("verifying signature for:", key)
		ref, err := name.ParseReference(key)
		if err != nil {
			sendResponse(nil, fmt.Sprintf("unable to parse image reference %q): %v", key, err), w)
			return
		}

		cosignPubKey, err := os.ReadFile(cosignPubKeyFile)
		if err != nil {
			fmt.Println(err, "unable to load cosign pub key", "cosignPubKeyFile", cosignPubKeyFile)
			os.Exit(1)
		}

		ecdsaKey, err := cosign.PemToECDSAKey(cosignPubKey)
		if err != nil {
			fmt.Println(err, "unable to convert cosign pub key to ecdsa key", err)
			os.Exit(1)
		}

		sigVerifier, err := signature.LoadECDSAVerifier(ecdsaKey, crypto.SHA256)
		if err != nil {
			fmt.Println(err, "unable to create sig verifier from cosign pub key", err)
			os.Exit(1)
		}

		// sigVerifier, err := signature.LoadPublicKeyRaw(cosignPubKey, crypto.SHA256)
		// if err != nil {
		// 	fmt.Println(err, "unable to create sig verifier from cosign pub key", err)
		// 	os.Exit(1)
		// }

		// sigVerifier, err := signature.LoadPublicKey(ctx, cosignPubKeyFile)
		// if err != nil {
		// 	fmt.Println(err, "unable to create sig verifier from cosign pub key", err)
		// 	os.Exit(1)
		// }

		_, _, err = cosign.VerifyImageSignatures(ctx, ref, &cosign.CheckOpts{
			// RekorClient:        rekorClient,
			RegistryClientOpts: co,
			// RootCerts:          rootCerts,
			SigVerifier: sigVerifier,
		})

		if err != nil {
			fmt.Println(err)
			sendResponse(nil, fmt.Sprintf("unable to verify image signatures: %v", err), w)
			return
		}

		fmt.Println("verified signature for:", key)

		results = append(results, externaldata.Item{
			Key:   key,
			Error: key + "_valid",
		})
	}

	sendResponse(&results, "", w)
}

// sendResponse sends back the response to Gatekeeper.
func sendResponse(results *[]externaldata.Item, systemErr string, w http.ResponseWriter) {
	response := externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       "ProviderResponse",
	}

	if results != nil {
		response.Response.Items = *results
	} else {
		response.Response.SystemError = systemErr
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		panic(err)
	}
}
