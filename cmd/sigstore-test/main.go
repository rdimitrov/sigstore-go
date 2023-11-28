package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"os"
	"strings"
)

// Q&A
// Q: In the signature manifest - Why do we have 3 `simplesigning` layers? Should we use all 3 or one is enough?
// cosign verify ghcr.io/rdimitrov/a-testrepo:latest --certificate-oidc-issuer=https://token.actions.githubusercontent.com --certificate-identity-regexp="^https://github.com/rdimitrov/a-testrepo/"
// VerifyData is a structure that contains all the data needed to run the verification
type VerifyData struct {
	name           string
	artifactDigest string
	issuer         string
	sanregex       string
	bundlePath     string
	bundle         *bundle.ProtobufBundle
}

func main() {
	// ghcr.io/rdimitrov/a-testrepo:latest
	// ghcr.io/stacklok/minder/server:latest
	// ghcr.io/stacklok/minder/helm/minder:0.20231127.836_ref.7d3b950
	// ghcr.io/rdimitrov/a-testrepo:unsigned

	// Get the verification data
	verifyData := VerifyExample() // using the example bundle
	if len(os.Args) > 1 {
		imageRef := os.Args[1]
		var err error
		verifyData, err = VerifyImage(imageRef) // using imageRef
		if err != nil {
			panic(err)
		}
	}
	// Run the verification
	RunVerification(verifyData)
}

// RunVerification runs the verification
func RunVerification(in *VerifyData) {
	trustedrootJSON, err := tuf.GetTrustedrootJSON("tuf-repo-cdn.sigstore.dev", "tufcache")
	if err != nil {
		panic(err)
	}

	trustedMaterial, err := root.NewTrustedRootFromJSON(trustedrootJSON)
	if err != nil {
		panic(err)
	}

	sev, err := verify.NewSignedEntityVerifier(trustedMaterial, verify.WithSignedCertificateTimestamps(1), verify.WithTransparencyLog(1), verify.WithOnlineVerification())
	if err != nil {
		panic(err)
	}

	digest, err := hex.DecodeString(in.artifactDigest)
	if err != nil {
		panic(err)
	}

	certID, err := verify.NewShortCertificateIdentity(in.issuer, "", "", in.sanregex)
	if err != nil {
		panic(err)
	}

	// Load the bundle
	var b *bundle.ProtobufBundle
	if in.bundlePath != "" {
		// Load from a path
		fmt.Println("Loading bundle from path:", in.bundlePath)
		b, err = bundle.LoadJSONFromPath(in.bundlePath)
		if err != nil {
			panic(err)
		}
	} else if in.bundle != nil {
		// Load from a bundle
		fmt.Println("Using the reference image bundle")
		b = in.bundle
		bexample, err := bundle.LoadJSONFromPath("./example-bundle.json")
		if err != nil {
			panic(err)
		}
		if bexample == nil {
			panic("Error loading bundle")
		}
	} else {
		panic("Either bundlePath or bundle must be supplied")
	}
	// TODO: verify the alg type
	result, err := sev.Verify(b, verify.NewPolicy(verify.WithArtifactDigest("sha512", digest), verify.WithCertificateIdentity(certID)))
	if err != nil {
		panic(err)
	}

	marshaled, err := json.MarshalIndent(result, "", "   ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(marshaled))
	fmt.Println("Verification successful for:", in.name)
}

// Apologies for the disruption, and thank you in advance for the understanding!
// buildBundle constructs the bundle from an image reference
func buildBundle(imageRef string) (string, string, *bundle.ProtobufBundle) {
	owner := os.Getenv("GITHUB_OWNER")
	token := os.Getenv("GITHUB_TOKEN")
	opts := []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)}
	craneOpts := []crane.Option{crane.WithAuthFromKeychain(authn.DefaultKeychain)}
	if owner != "" && token != "" {
		// need to authenticate in case artifact is private
		auth := githubAuthenticator{owner, token}
		// opts := []ociremote.Option{ociremote.WithRemoteOptions(remote.WithAuth(auth))}
		opts = []remote.Option{remote.WithAuth(auth)}
		craneOpts = []crane.Option{crane.WithAuth(auth)}
	}

	// 1. Get the image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		panic("Error parsing reference")
	}
	fmt.Println("Got reference:", ref)

	// 2. Get the digest of the image reference
	desc, err := remote.Get(ref, opts...)
	if err != nil {
		panic("Error getting reference")
	}
	digest := ref.Context().Digest(desc.Digest.String())
	h, err := v1.NewHash(digest.Identifier())
	if err != nil {
		panic("Error getting hash")
	}

	// 3. Construct the signature reference
	st := digest.Context().Tag(normalizeWithSeparator(h, "", "sig", "-"))

	// 4. Get the manifest of the signature
	manifest, err := crane.Manifest(st.Name(), craneOpts...)
	if err != nil {
		panic("Error getting manifest")
	}
	mf, err := v1.ParseManifest(bytes.NewReader(manifest))
	if err != nil {
		panic("Error unmarshaling json")
	}
	manifestLayer := mf.Layers[0]
	// 5. Get the simplesigning blob - optionally verify the image digest matches the simplesigning blob
	//src := digest.Context().Digest(normalizeWithSeparator(manifestLayer.Digest, "", "", ":"))
	//layer, err := crane.PullLayer(src.String(), craneOpts...)
	//if err != nil {
	//	panic("Error pulling layer")
	//}
	//blob, err := layer.Compressed()
	//if err != nil {
	//	panic("Error getting blob")
	//}
	//blob = blob

	manBun := manifestLayer.Annotations["dev.sigstore.cosign/bundle"]
	//bundleBytes, err := base64.StdEncoding.DecodeString(manBun)
	//if err != nil {
	//	panic("Error decoding bundle")
	//}
	manSig := manifestLayer.Annotations["dev.cosignproject.cosign/signature"]
	manSigb, err := base64.StdEncoding.DecodeString(manSig)
	if err != nil {
		panic("Error decoding manSig")
	}
	var jsonData map[string]interface{}
	err = json.Unmarshal([]byte(manBun), &jsonData)
	if err != nil {
		panic("Error unmarshaling json")
	}
	signedEntryTimestamp, ok1 := jsonData["SignedEntryTimestamp"].(string)
	if !ok1 {
		panic("Error getting SignedEntryTimestamp")
	}
	signedEntryTimestampb, err := base64.StdEncoding.DecodeString(signedEntryTimestamp)
	if err != nil {
		panic("Error decoding signedEntryTimestamp")
	}
	logIndex, ok2 := jsonData["Payload"].(map[string]interface{})["logIndex"].(float64)
	if !ok2 {
		panic("Error getting logIndex")
	}
	logID, ok3 := jsonData["Payload"].(map[string]interface{})["logID"].(string)
	if !ok3 {
		panic("Error getting logID")
	}
	logIDb, err := hex.DecodeString(logID)
	if err != nil {
		panic("Error decoding logID")
	}
	integratedTime, ok4 := jsonData["Payload"].(map[string]interface{})["integratedTime"].(float64)
	if !ok4 {
		panic("Error getting integratedTime")
	}
	body, ok5 := jsonData["Payload"].(map[string]interface{})["body"].(string)
	if !ok5 {
		panic("Error getting body")
	}
	bodyBytes, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		panic("Error decoding bundle")
	}
	err = json.Unmarshal(bodyBytes, &jsonData)
	if err != nil {
		panic("Error unmarshaling json")
	}
	apiVersion := jsonData["apiVersion"].(string)
	kind := jsonData["kind"].(string)
	pemString := manifestLayer.Annotations["dev.sigstore.cosign/certificate"]
	// construct the DER encoded version of the PEM certificate
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		panic("Error decoding PEM block")
	}
	signingCert := protocommon.X509Certificate{
		RawBytes: block.Bytes,
	}

	var msgHashAlg protocommon.HashAlgorithm
	switch manifestLayer.Digest.Algorithm {
	case "sha256":
		msgHashAlg = protocommon.HashAlgorithm_SHA2_256
	default:
		panic("Unknown digest algorithm")
	}

	digb, err := hex.DecodeString(manifestLayer.Digest.Hex)
	if err != nil {
		panic("Error decoding digest")
	}
	// Construct bundle
	pb := protobundle.Bundle{
		MediaType: bundle.SigstoreBundleMediaType01,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_X509CertificateChain{
				X509CertificateChain: &protocommon.X509CertificateChain{
					Certificates: []*protocommon.X509Certificate{&signingCert},
				},
			},
			TlogEntries: []*protorekor.TransparencyLogEntry{
				{
					// Got this from dev.sigstore.cosign/bundle.Payload.LogIndex
					LogIndex: int64(logIndex),
					// Got this from dev.sigstore.cosign/bundle.Payload.LogID
					LogId: &protocommon.LogId{
						KeyId: logIDb,
					},
					// Hardcoded this
					KindVersion: &protorekor.KindVersion{
						Kind:    kind,
						Version: apiVersion,
					},
					// Got this from dev.sigstore.cosign/bundle.Payload.IntegratedTime
					IntegratedTime: int64(integratedTime),
					// Got this from dev.sigstore.cosign/bundle.SignedEntryTimestamp
					InclusionPromise: &protorekor.InclusionPromise{
						SignedEntryTimestamp: signedEntryTimestampb, // []byte(signedEntryTimestamp),
					},
					InclusionProof: nil,
					// Got this from dev.sigstore.cosign/bundle.Payload.Body
					CanonicalizedBody: bodyBytes,
				},
			},
			// Got this from dev.sigstore.cosign/bundle.SignedEntryTimestamp
			TimestampVerificationData: nil,
			//TimestampVerificationData: &protobundle.TimestampVerificationData{
			//	Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{
			//		{
			//			SignedTimestamp: []byte("MEUCIQCgowLE0eEnW34AOjdWE/xZcFiX04ROVTCWRtke8b6jBQIgOO6X8nvawJsZeWm+AEueqB+tQo2HObYiBVsDv1Cskhc="),
			//		},
			//	},
			//},
		},
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: msgHashAlg,
					// Got this from signature's manifest - layer.digest
					Digest: digb,
				},
				// Got this from signature's manifest - layer.dev.cosignproject.cosign/signature
				Signature: manSigb,
			},
		},
	}
	bun, err := bundle.NewProtobufBundle(&pb)
	if err != nil {
		panic(err)
	}
	return ref.Context().RepositoryStr(), manifestLayer.Digest.Hex, bun
}

// VerifyImage returns a verification data bundle from an image reference
func VerifyImage(imageRef string) (*VerifyData, error) {
	b := &VerifyData{
		name:   imageRef,
		issuer: "https://token.actions.githubusercontent.com",
	}

	repo, dig, bun := buildBundle(imageRef)
	b.bundle = bun
	parts := strings.SplitN(repo, "/", -1)
	b.sanregex = fmt.Sprintf("^https://github.com/%s/%s/", parts[0], parts[1])
	b.artifactDigest = dig
	return b, nil
}

// VerifyExample returns the example bundle use case
func VerifyExample() *VerifyData {
	return &VerifyData{
		name:           "example",
		artifactDigest: "76176ffa33808b54602c7c35de5c6e9a4deb96066dba6533f50ac234f4f1f4c6b3527515dc17c06fbe2860030f410eee69ea20079bd3a2c6f3dcf3b329b10751",
		issuer:         "https://token.actions.githubusercontent.com",
		sanregex:       "^https://github.com/sigstore/sigstore-js/",
		bundlePath:     "./example-bundle.json",
	}
}

// normalizeWithSeparator turns image digests into tags with optional prefix & suffix:
// sha256:d34db33f -> [prefix]sha256[algorithmSeparator]d34db33f[.suffix]
func normalizeWithSeparator(h v1.Hash, prefix string, suffix string, algorithmSeparator string) string {
	if suffix == "" {
		return fmt.Sprint(prefix, h.Algorithm, algorithmSeparator, h.Hex)
	}
	return fmt.Sprint(prefix, h.Algorithm, algorithmSeparator, h.Hex, ".", suffix)
}

type githubAuthenticator struct{ username, password string }

func (g githubAuthenticator) Authorization() (*authn.AuthConfig, error) {
	return &authn.AuthConfig{
		Username: g.username,
		Password: g.password,
	}, nil
}
