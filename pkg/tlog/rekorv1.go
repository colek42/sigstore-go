// Copyright 2026 The Sigstore Authors.
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

package tlog

// This file replaces sigstore-go's use of rekor's generated Swagger models
// (pkg/generated/models), its type registry (pkg/types and the dsse v0.0.1,
// hashedrekord v0.0.1 and intoto v0.0.2 type packages) and pkg/verify. Those
// packages link the go-openapi stack (runtime, validate, spec, loads,
// analysis, strfmt, errors, swag and its 15 submodules) and rekor's HTTP
// client, none of which a verifier calls. The behaviour reproduced is exactly
// the subset sigstore-go reaches: parse a canonicalized v1 body, validate it,
// read its signature, key and digests, and verify an inclusion proof and a
// signed checkpoint. The crypto stays rekor's: rekor/pkg/pki/x509 and
// rekor/pkg/util are imported unchanged (they link no go-openapi).

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// b64 is strfmt.Base64: bytes carried as standard base64 in JSON.
type b64 []byte

// rekorV1Entry is one of the three entry types sigstore-go registers.
type rekorV1Entry interface{ rekorV1() }

type hashedrekordV001Entry struct{ HashedRekordObj hashedrekordV001Schema }
type dsseV001Entry struct{ DSSEObj dsseV001Schema }
type intotoV002Entry struct{ IntotoObj intotoV002Schema }

func (*hashedrekordV001Entry) rekorV1() {}
func (*dsseV001Entry) rekorV1()         {}
func (*intotoV002Entry) rekorV1()       {}

// The schema structs mirror rekor's generated models field for field, so the
// accessors in entry.go read them unchanged.
type hashAlgValue struct {
	Algorithm *string
	Value     *string
}

type hashedrekordV001Schema struct {
	Data      *hashedrekordV001SchemaData
	Signature *hashedrekordV001SchemaSignature
}
type hashedrekordV001SchemaData struct{ Hash *hashAlgValue }
type hashedrekordV001SchemaSignature struct {
	Content   b64
	PublicKey *hashedrekordV001SchemaSignaturePublicKey
}
type hashedrekordV001SchemaSignaturePublicKey struct{ Content b64 }

type dsseV001Schema struct {
	EnvelopeHash    *hashAlgValue
	PayloadHash     *hashAlgValue
	ProposedContent *dsseV001SchemaProposedContent
	Signatures      []*dsseV001SchemaSignaturesItems0
}
type dsseV001SchemaProposedContent struct {
	Envelope  *string
	Verifiers []b64
}
type dsseV001SchemaSignaturesItems0 struct {
	Signature *string
	Verifier  *b64
}

type intotoV002Schema struct{ Content *intotoV002SchemaContent }
type intotoV002SchemaContent struct {
	Envelope    *intotoV002SchemaContentEnvelope
	Hash        *hashAlgValue
	PayloadHash *hashAlgValue
}
type intotoV002SchemaContentEnvelope struct {
	Payload     b64
	PayloadType *string
	Signatures  []*intotoV002SchemaContentEnvelopeSignaturesItems0
}
type intotoV002SchemaContentEnvelopeSignaturesItems0 struct {
	Keyid     string
	PublicKey *b64
	Sig       *b64
}

var errRequired = errors.New("rekor v1 entry: a required field is missing")

// validateHashAlgValue is the generated Validate of every {algorithm, value}
// object: algorithm required and in the enum (case-sensitive), value required.
func validateHashAlgValue(h *hashAlgValue, enum ...string) error {
	if h.Algorithm == nil {
		return errRequired
	}
	if !slices.Contains(enum, *h.Algorithm) {
		return fmt.Errorf("rekor v1 entry: algorithm %q is not one of %v", *h.Algorithm, enum)
	}
	if h.Value == nil {
		return errRequired
	}
	return nil
}

// validate is models.HashedrekordV001Schema.Validate.
func (m *hashedrekordV001Schema) validate() error {
	if m.Data == nil || m.Signature == nil {
		return errRequired
	}
	if m.Data.Hash != nil {
		if err := validateHashAlgValue(m.Data.Hash, "sha256", "sha384", "sha512"); err != nil {
			return err
		}
	}
	return nil
}

var base64Pattern = regexp.MustCompile(`^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})$`)

// validate is models.DSSEV001Schema.Validate.
func (m *dsseV001Schema) validate() error {
	if m.EnvelopeHash != nil {
		if err := validateHashAlgValue(m.EnvelopeHash, "sha256"); err != nil {
			return err
		}
	}
	if m.PayloadHash != nil {
		if err := validateHashAlgValue(m.PayloadHash, "sha256"); err != nil {
			return err
		}
	}
	if m.ProposedContent != nil {
		if m.ProposedContent.Envelope == nil || m.ProposedContent.Verifiers == nil {
			return errRequired
		}
		if len(m.ProposedContent.Verifiers) < 1 {
			return errRequired
		}
	}
	if m.Signatures != nil {
		if len(m.Signatures) < 1 {
			return errRequired
		}
		for _, s := range m.Signatures {
			if s == nil {
				continue
			}
			if s.Signature == nil {
				return errRequired
			}
			if !base64Pattern.MatchString(*s.Signature) {
				return errors.New("rekor v1 entry: dsse signature is not base64")
			}
			if s.Verifier == nil {
				return errRequired
			}
		}
	}
	return nil
}

// validate is models.IntotoV002Schema.Validate.
func (m *intotoV002Schema) validate() error {
	if m.Content == nil || m.Content.Envelope == nil {
		return errRequired
	}
	env := m.Content.Envelope
	if env.PayloadType == nil || env.Signatures == nil || len(env.Signatures) < 1 {
		return errRequired
	}
	for _, s := range env.Signatures {
		if s == nil {
			continue
		}
		if s.PublicKey == nil || s.Sig == nil {
			return errRequired
		}
	}
	if m.Content.Hash != nil {
		if err := validateHashAlgValue(m.Content.Hash, "sha256"); err != nil {
			return err
		}
	}
	if m.Content.PayloadHash != nil {
		if err := validateHashAlgValue(m.Content.PayloadHash, "sha256"); err != nil {
			return err
		}
	}
	return nil
}

// b64decode is the decode rekor's per-type DecodeEntry repeats inline.
func b64decode(s, what string) (b64, error) {
	outb := make([]byte, base64.StdEncoding.DecodedLen(len(s)))
	n, err := base64.StdEncoding.Decode(outb, []byte(s))
	if err != nil {
		return nil, fmt.Errorf("failed parsing base64 data for %s: %w", what, err)
	}
	return b64(outb[:n]), nil
}

func hashFrom(raw map[string]any) *hashAlgValue {
	h := &hashAlgValue{}
	if alg, ok := raw["algorithm"].(string); ok {
		h.Algorithm = &alg
	}
	if val, ok := raw["value"].(string); ok {
		h.Value = &val
	}
	return h
}

// decodeHashedrekord is hashedrekord v0.0.1 DecodeEntry for the input a JSON
// decode produces (exact keys, wrong-typed values ignored).
func decodeHashedrekord(input any, out *hashedrekordV001Schema) error {
	mm, ok := input.(map[string]any)
	if !ok {
		return fmt.Errorf("unsupported input type %T for DecodeEntry", input)
	}
	var m hashedrekordV001Schema
	if sigRaw, ok := mm["signature"].(map[string]any); ok {
		m.Signature = &hashedrekordV001SchemaSignature{}
		if c, ok := sigRaw["content"].(string); ok && c != "" {
			b, err := b64decode(c, "signature content")
			if err != nil {
				return err
			}
			m.Signature.Content = b
		}
		if pkRaw, ok := sigRaw["publicKey"].(map[string]any); ok {
			m.Signature.PublicKey = &hashedrekordV001SchemaSignaturePublicKey{}
			if c, ok := pkRaw["content"].(string); ok && c != "" {
				b, err := b64decode(c, "public key content")
				if err != nil {
					return err
				}
				m.Signature.PublicKey.Content = b
			}
		}
	}
	if dataRaw, ok := mm["data"].(map[string]any); ok {
		if hRaw, ok := dataRaw["hash"].(map[string]any); ok {
			m.Data = &hashedrekordV001SchemaData{Hash: hashFrom(hRaw)}
		}
	}
	*out = m
	return nil
}

// decodeDSSE is dsse v0.0.1 DecodeEntry for JSON-decoded input (the
// []string verifiers branch is unreachable from encoding/json).
func decodeDSSE(input any, out *dsseV001Schema) error {
	mm, ok := input.(map[string]any)
	if !ok {
		return fmt.Errorf("unsupported input type %T for DecodeEntry", input)
	}
	var m dsseV001Schema
	if pcRaw, ok := mm["proposedContent"].(map[string]any); ok {
		m.ProposedContent = &dsseV001SchemaProposedContent{}
		if env, ok := pcRaw["envelope"].(string); ok {
			m.ProposedContent.Envelope = &env
		}
		if vsIF, ok := pcRaw["verifiers"].([]any); ok {
			m.ProposedContent.Verifiers = make([]b64, 0, len(vsIF))
			for _, it := range vsIF {
				if s, ok := it.(string); ok && s != "" {
					b, err := b64decode(s, "verifier")
					if err != nil {
						return err
					}
					m.ProposedContent.Verifiers = append(m.ProposedContent.Verifiers, b)
				}
			}
		}
	}
	if sigs, ok := mm["signatures"].([]any); ok {
		m.Signatures = make([]*dsseV001SchemaSignaturesItems0, 0, len(sigs))
		for _, s := range sigs {
			if sm, ok := s.(map[string]any); ok {
				item := &dsseV001SchemaSignaturesItems0{}
				if sig, ok := sm["signature"].(string); ok {
					item.Signature = &sig
				}
				if vr, ok := sm["verifier"].(string); ok && vr != "" {
					b, err := b64decode(vr, "signature verifier")
					if err != nil {
						return err
					}
					item.Verifier = &b
				}
				m.Signatures = append(m.Signatures, item)
			}
		}
	}
	if eh, ok := mm["envelopeHash"].(map[string]any); ok {
		m.EnvelopeHash = hashFrom(eh)
	}
	if ph, ok := mm["payloadHash"].(map[string]any); ok {
		m.PayloadHash = hashFrom(ph)
	}
	*out = m
	return nil
}

// decodeIntoto is intoto v0.0.2 DecodeEntry for JSON-decoded input (the
// []map[string]any signatures branch is unreachable from encoding/json).
func decodeIntoto(input any, out *intotoV002Schema) error {
	mm, ok := input.(map[string]any)
	if !ok {
		return fmt.Errorf("unsupported input type %T for DecodeEntry", input)
	}
	var m intotoV002Schema
	m.Content = &intotoV002SchemaContent{Envelope: &intotoV002SchemaContentEnvelope{}}
	if c, ok := mm["content"].(map[string]any); ok {
		if env, ok := c["envelope"].(map[string]any); ok {
			if pt, ok := env["payloadType"].(string); ok {
				m.Content.Envelope.PayloadType = &pt
			}
			if p, ok := env["payload"].(string); ok && p != "" {
				b, err := b64decode(p, "payload")
				if err != nil {
					return err
				}
				m.Content.Envelope.Payload = b
			}
			if sigs, ok := env["signatures"].([]any); ok {
				m.Content.Envelope.Signatures = make([]*intotoV002SchemaContentEnvelopeSignaturesItems0, 0, len(sigs))
				for _, s := range sigs {
					if sm, ok := s.(map[string]any); ok {
						item := &intotoV002SchemaContentEnvelopeSignaturesItems0{}
						if kid, ok := sm["keyid"].(string); ok {
							item.Keyid = kid
						}
						if sig, ok := sm["sig"].(string); ok {
							b, err := b64decode(sig, "signature")
							if err != nil {
								return err
							}
							item.Sig = &b
						}
						if pk, ok := sm["publicKey"].(string); ok {
							b, err := b64decode(pk, "public key")
							if err != nil {
								return err
							}
							item.PublicKey = &b
						}
						m.Content.Envelope.Signatures = append(m.Content.Envelope.Signatures, item)
					}
				}
			}
		}
		if h, ok := c["hash"].(map[string]any); ok {
			m.Content.Hash = hashFrom(h)
		}
		if ph, ok := c["payloadHash"].(map[string]any); ok {
			m.Content.PayloadHash = hashFrom(ph)
		}
	}
	*out = m
	return nil
}

// unmarshalRekorV1Entry is models.UnmarshalProposedEntry (one decode of
// kind, apiVersion and spec; numbers kept as json.Number) followed by
// types.UnmarshalEntry, for the kinds sigstore-go registers (hashedrekord
// 0.0.1, dsse 0.0.1, intoto 0.0.2), whose version maps match exactly. Any
// other kind, rekor's included, was "could not unmarshal entry for kind".
func unmarshalRekorV1Entry(body []byte) (rekorV1Entry, error) {
	var pe struct {
		Kind       string  `json:"kind"`
		APIVersion *string `json:"apiVersion"`
		Spec       any     `json:"spec"`
	}
	if err := jsonDecode(body, &pe); err != nil {
		return nil, err
	}
	if pe.Kind == "" {
		return nil, errors.New("kind in body is required")
	}
	var want string
	switch pe.Kind {
	case "hashedrekord", "dsse":
		want = "0.0.1"
	case "intoto":
		want = "0.0.2"
	default:
		return nil, fmt.Errorf("could not unmarshal entry for kind '%v'", pe.Kind)
	}
	if pe.APIVersion == nil {
		return nil, errors.New("api version cannot be nil")
	}
	if *pe.APIVersion != want {
		return nil, fmt.Errorf("%s implementation for version '%v' not found: unable to locate entry for version %s", pe.Kind, *pe.APIVersion, *pe.APIVersion)
	}
	switch pe.Kind {
	case "hashedrekord":
		e := &hashedrekordV001Entry{}
		return e, e.unmarshal(pe.Spec)
	case "dsse":
		e := &dsseV001Entry{}
		return e, e.unmarshal(pe.Spec)
	default:
		e := &intotoV002Entry{}
		return e, e.unmarshal(pe.Spec)
	}
}

// jsonDecode is runtime.JSONConsumer().Consume: the first JSON value, with
// UseNumber.
func jsonDecode(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	return dec.Decode(v)
}

// unmarshal is hashedrekord v0.0.1 V001Entry.Unmarshal.
func (v *hashedrekordV001Entry) unmarshal(spec any) error {
	if err := decodeHashedrekord(spec, &v.HashedRekordObj); err != nil {
		return err
	}
	if err := v.HashedRekordObj.validate(); err != nil {
		return err
	}
	return v.crossValidate()
}

// crossValidate is hashedrekord v0.0.1 V001Entry.validate.
func (v *hashedrekordV001Entry) crossValidate() error {
	sig := v.HashedRekordObj.Signature
	if sig == nil {
		return errors.New("missing signature")
	}
	sigObj, err := x509.NewSignatureWithOpts(bytes.NewReader(sig.Content), options.WithED25519ph())
	if err != nil {
		return err
	}
	key := sig.PublicKey
	if key == nil {
		return errors.New("missing public key")
	}
	keyObj, err := x509.NewPublicKey(bytes.NewReader(key.Content))
	if err != nil {
		return err
	}
	data := v.HashedRekordObj.Data
	if data == nil {
		return errors.New("missing data")
	}
	hash := data.Hash
	if hash == nil {
		return errors.New("missing hash")
	}
	var alg crypto.Hash
	algName := ""
	if hash.Algorithm != nil {
		algName = *hash.Algorithm
	}
	switch algName {
	case "sha384":
		if len(*hash.Value) != crypto.SHA384.Size()*2 {
			return errors.New("invalid value for hash")
		}
		alg = crypto.SHA384
	case "sha512":
		if len(*hash.Value) != crypto.SHA512.Size()*2 {
			return errors.New("invalid value for hash")
		}
		alg = crypto.SHA512
	default:
		if len(*hash.Value) != crypto.SHA256.Size()*2 {
			return errors.New("invalid value for hash")
		}
		alg = crypto.SHA256
	}
	decoded, err := hex.DecodeString(*hash.Value)
	if err != nil {
		return err
	}
	if err := sigObj.Verify(nil, keyObj, options.WithDigest(decoded), options.WithCryptoSignerOpts(alg)); err != nil {
		return fmt.Errorf("verifying signature: %w", err)
	}
	return nil
}

// unmarshal is dsse v0.0.1 V001Entry.Unmarshal (index-key extraction, which
// only feeds rekor's search index, is left out: nothing here reads it).
func (v *dsseV001Entry) unmarshal(spec any) error {
	dsseObj := &dsseV001Schema{}
	if err := decodeDSSE(spec, dsseObj); err != nil {
		return err
	}
	if err := dsseObj.validate(); err != nil {
		return err
	}
	if dsseObj.ProposedContent == nil {
		if dsseObj.EnvelopeHash == nil || dsseObj.PayloadHash == nil || len(dsseObj.Signatures) == 0 {
			return errors.New("either proposedContent or envelopeHash, payloadHash, and signatures must be present")
		}
		v.DSSEObj = *dsseObj
		return nil
	}
	if dsseObj.EnvelopeHash != nil || dsseObj.PayloadHash != nil || len(dsseObj.Signatures) != 0 {
		return errors.New("either proposedContent or envelopeHash, payloadHash, and signatures must be present but not both")
	}
	env := &dsse.Envelope{}
	if dsseObj.ProposedContent.Envelope == nil {
		return errors.New("proposed content envelope is missing")
	}
	if err := json.Unmarshal([]byte(*dsseObj.ProposedContent.Envelope), env); err != nil {
		return err
	}
	if len(env.Signatures) == 0 {
		return errors.New("DSSE envelope must contain 1 or more signatures")
	}
	allPubKeyBytes := make([][]byte, 0)
	for _, publicKey := range dsseObj.ProposedContent.Verifiers {
		if publicKey == nil {
			return errors.New("an invalid null verifier was provided in ProposedContent")
		}
		allPubKeyBytes = append(allPubKeyBytes, publicKey)
	}
	sigToKeyMap, err := verifyEnvelopeDSSE(allPubKeyBytes, env)
	if err != nil {
		return err
	}
	sortedSigs := make([]string, 0, len(sigToKeyMap))
	for sig := range sigToKeyMap {
		sortedSigs = append(sortedSigs, sig)
	}
	sort.Strings(sortedSigs)
	for i, sig := range sortedSigs {
		canonicalizedKey, err := sigToKeyMap[sig].CanonicalValue()
		if err != nil {
			return err
		}
		k := b64(canonicalizedKey)
		dsseObj.Signatures = append(dsseObj.Signatures, &dsseV001SchemaSignaturesItems0{Signature: &sortedSigs[i], Verifier: &k})
	}
	decodedPayload, err := env.DecodeB64Payload()
	if err != nil {
		return err
	}
	payloadHash := sha256.Sum256(decodedPayload)
	alg, ph := "sha256", hex.EncodeToString(payloadHash[:])
	dsseObj.PayloadHash = &hashAlgValue{Algorithm: &alg, Value: &ph}
	envelopeHash := sha256.Sum256([]byte(*dsseObj.ProposedContent.Envelope))
	alg2, eh := "sha256", hex.EncodeToString(envelopeHash[:])
	dsseObj.EnvelopeHash = &hashAlgValue{Algorithm: &alg2, Value: &eh}
	v.DSSEObj = *dsseObj
	v.DSSEObj.ProposedContent = nil
	return nil
}

// verifyEnvelopeDSSE is dsse v0.0.1 verifyEnvelope.
func verifyEnvelopeDSSE(allPubKeyBytes [][]byte, env *dsse.Envelope) (map[string]*x509.PublicKey, error) {
	verifierBySig := make(map[string]*x509.PublicKey)
	allSigs := make(map[string]struct{})
	for _, sig := range env.Signatures {
		allSigs[sig.Sig] = struct{}{}
	}
	for _, pubKeyBytes := range allPubKeyBytes {
		if len(allSigs) == 0 {
			break
		}
		key, err := x509.NewPublicKey(bytes.NewReader(pubKeyBytes))
		if err != nil {
			return nil, fmt.Errorf("could not parse public key as x509: %w", err)
		}
		vfr, err := signature.LoadVerifier(key.CryptoPubKey(), crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("could not load verifier: %w", err)
		}
		dsseVfr, err := dsse.NewEnvelopeVerifier(&sigdsse.VerifierAdapter{SignatureVerifier: vfr})
		if err != nil {
			return nil, fmt.Errorf("could not use public key as a dsse verifier: %w", err)
		}
		accepted, err := dsseVfr.Verify(context.Background(), env)
		if err != nil {
			return nil, fmt.Errorf("could not verify envelope: %w", err)
		}
		for _, accept := range accepted {
			delete(allSigs, accept.Sig.Sig)
			verifierBySig[accept.Sig.Sig] = key
		}
	}
	if len(allSigs) > 0 {
		return nil, errors.New("all signatures must have a key that verifies it")
	}
	return verifierBySig, nil
}

// unmarshal is intoto v0.0.2 V002Entry.Unmarshal.
func (v *intotoV002Entry) unmarshal(spec any) error {
	if err := decodeIntoto(spec, &v.IntotoObj); err != nil {
		return err
	}
	if err := v.IntotoObj.validate(); err != nil {
		return err
	}
	if string(v.IntotoObj.Content.Envelope.Payload) == "" {
		return nil
	}
	env := &dsse.Envelope{
		Payload:     string(v.IntotoObj.Content.Envelope.Payload),
		PayloadType: *v.IntotoObj.Content.Envelope.PayloadType,
	}
	allPubKeyBytes := make([][]byte, 0)
	for i, sig := range v.IntotoObj.Content.Envelope.Signatures {
		if sig == nil {
			// rekor: slices.Delete(s, i, i), which deletes nothing
			v.IntotoObj.Content.Envelope.Signatures = slices.Delete(v.IntotoObj.Content.Envelope.Signatures, i, i)
			continue
		}
		env.Signatures = append(env.Signatures, dsse.Signature{KeyID: sig.Keyid, Sig: string(*sig.Sig)})
		allPubKeyBytes = append(allPubKeyBytes, *sig.PublicKey)
	}
	if err := verifyEnvelopeIntoto(allPubKeyBytes, env); err != nil {
		return err
	}
	decodedPayload, err := base64.StdEncoding.DecodeString(string(v.IntotoObj.Content.Envelope.Payload))
	if err != nil {
		return fmt.Errorf("could not decode envelope payload: %w", err)
	}
	h := sha256.Sum256(decodedPayload)
	alg, ph := "sha256", hex.EncodeToString(h[:])
	v.IntotoObj.Content.PayloadHash = &hashAlgValue{Algorithm: &alg, Value: &ph}
	return nil
}

// intotoVerifier is intoto v0.0.2's verifier adapter: an empty key ID and a
// nil public key, so the dsse library tries it against every signature.
type intotoVerifier struct{ v signature.Verifier }

func (*intotoVerifier) KeyID() (string, error)   { return "", nil }
func (*intotoVerifier) Public() crypto.PublicKey { return nil }
func (v *intotoVerifier) Verify(_ context.Context, data, sig []byte) error {
	if v.v == nil {
		return errors.New("nil verifier")
	}
	return v.v.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
}

// verifyEnvelopeIntoto is intoto v0.0.2 verifyEnvelope.
func verifyEnvelopeIntoto(allPubKeyBytes [][]byte, env *dsse.Envelope) error {
	allSigs := make(map[string]struct{})
	for _, sig := range env.Signatures {
		allSigs[sig.Sig] = struct{}{}
	}
	for _, pubKeyBytes := range allPubKeyBytes {
		key, err := x509.NewPublicKey(bytes.NewReader(pubKeyBytes))
		if err != nil {
			return fmt.Errorf("could not parse public key as x509: %w", err)
		}
		vfr, err := signature.LoadVerifier(key.CryptoPubKey(), crypto.SHA256)
		if err != nil {
			return fmt.Errorf("could not load verifier: %w", err)
		}
		dsseVfr, err := dsse.NewEnvelopeVerifier(&intotoVerifier{v: vfr})
		if err != nil {
			return fmt.Errorf("could not use public key as a dsse verifier: %w", err)
		}
		accepted, err := dsseVfr.Verify(context.Background(), env)
		if err != nil {
			return fmt.Errorf("could not verify envelope: %w", err)
		}
		for _, accept := range accepted {
			delete(allSigs, accept.Sig.Sig)
		}
	}
	if len(allSigs) > 0 {
		return errors.New("all signatures must have a key that verifies it")
	}
	return nil
}

// validateRekorV1 is the field validation tlog.ValidateEntry ran per type.
func validateRekorV1(e rekorV1Entry) error {
	switch e := e.(type) {
	case *dsseV001Entry:
		return e.DSSEObj.validate()
	case *hashedrekordV001Entry:
		return e.HashedRekordObj.validate()
	case *intotoV002Entry:
		return e.IntotoObj.validate()
	default:
		return fmt.Errorf("unsupported entry type: %T", e)
	}
}

// verifyRekorV1Inclusion is rekor verify.VerifyInclusion followed by
// verify.VerifyCheckpointSignature, on the values sigstore-go built its
// models.LogEntryAnon from.
func verifyRekorV1Inclusion(body []byte, logIndex, treeSize int64, hashes [][]byte, rootHash []byte, checkpoint string, verifier signature.Verifier) error {
	leafHash := rfc6962.DefaultHasher.HashLeaf(body)
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(logIndex), uint64(treeSize), leafHash, hashes, rootHash); err != nil { //nolint:gosec
		return err
	}
	sth := &util.SignedCheckpoint{}
	if err := sth.UnmarshalText([]byte(checkpoint)); err != nil {
		return fmt.Errorf("unmarshalling log entry checkpoint to SignedCheckpoint: %w", err)
	}
	if !sth.Verify(verifier) {
		return errors.New("signature on checkpoint did not verify")
	}
	if !bytes.Equal(rootHash, sth.Hash) {
		return fmt.Errorf("proof root hash does not match signed tree head, expected %s got %s",
			hex.EncodeToString(rootHash), hex.EncodeToString(sth.Hash))
	}
	return nil
}

// rekorV1Kind and rekorV1Version are ProposedEntry.Kind and EntryImpl.APIVersion.
func rekorV1Kind(e rekorV1Entry) string {
	switch e.(type) {
	case *hashedrekordV001Entry:
		return "hashedrekord"
	case *dsseV001Entry:
		return "dsse"
	default:
		return "intoto"
	}
}

func rekorV1Version(e rekorV1Entry) string {
	if _, ok := e.(*intotoV002Entry); ok {
		return "0.0.2"
	}
	return "0.0.1"
}
