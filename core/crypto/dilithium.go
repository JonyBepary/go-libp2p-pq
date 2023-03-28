package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/JonyBepary/go-libp2p-pq/core/crypto"
	pb "github.com/JonyBepary/go-libp2p-pq/core/crypto/pb"
	"github.com/golang/protobuf/proto"
	"github.com/theQRL/go-libp2p-qrl/protos"
	"github.com/theQRL/go-qrllib/common"
	"github.com/theQRL/go-qrllib/dilithium"
)

type DilithiumPrivateKey struct {
	pb *protos.DilithiumKeys
}

type DilithiumPublicKey struct {
	pb *protos.DilithiumPublicKey
}

func GenerateDilithiumKey(src io.Reader) (crypto.PrivKey, crypto.PubKey, error) {
	if !isLoaded {
		return nil, nil, errors.New("LoadAllExtendedKeyTypes before using")
	}
	d := dilithium.New()
	sk := d.GetSK()
	pk := d.GetPK()
	seed := d.GetSeed()
	return &DilithiumPrivateKey{
			pb: &protos.DilithiumKeys{
				Sk:   sk[:],
				Pk:   pk[:],
				Seed: seed[:],
			},
		},
		&DilithiumPublicKey{
			pb: &protos.DilithiumPublicKey{
				Pk: pk[:],
			},
		},
		nil
}

func (sk *DilithiumPrivateKey) Type() pb.KeyType {
	return mapExtendedKeyTypes[LATTICE]
}

func (sk *DilithiumPrivateKey) Bytes() ([]byte, error) {
	return crypto.MarshalPrivateKey(sk)
}

func (sk *DilithiumPrivateKey) Raw() ([]byte, error) {
	return proto.Marshal(sk.pb)
}

func (sk *DilithiumPrivateKey) Equals(k crypto.Key) bool {
	return basicEquals(sk, k)
}

func (sk *DilithiumPrivateKey) Sign(data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	hash := h.Sum(nil)
	var pkSized [dilithium.PKSizePacked]uint8
	var skSized [dilithium.SKSizePacked]uint8
	var seed [common.SeedSize]uint8

	copy(pkSized[:], sk.pb.Pk)
	copy(skSized[:], sk.pb.Sk)
	copy(seed[:], sk.pb.Seed)

	//d := dilithium.NewFromKeys(&pkSized, &skSized)
	d := dilithium.NewDilithiumFromSeed(seed)
	signature := d.Seal(hash)

	expectedPK := d.GetPK()
	if hex.EncodeToString(expectedPK[:]) != hex.EncodeToString(sk.pb.Pk) {
		return nil, fmt.Errorf("pk mismatch")
	}

	expectedSK := d.GetSK()
	if hex.EncodeToString(expectedSK[:]) != hex.EncodeToString(sk.pb.Sk) {
		return nil, fmt.Errorf("sk mismatch")
	}

	return signature, nil
}

func (sk *DilithiumPrivateKey) GetPublic() crypto.PubKey {
	return &DilithiumPublicKey{
		pb: &protos.DilithiumPublicKey{
			Pk: sk.pb.Pk,
		},
	}
}

func (pk *DilithiumPublicKey) Bytes() ([]byte, error) {
	return crypto.MarshalPublicKey(pk)
}

func (pk *DilithiumPublicKey) Type() pb.KeyType {
	return mapExtendedKeyTypes[LATTICE]
}

func (pk *DilithiumPublicKey) Raw() ([]byte, error) {
	return proto.Marshal(pk.pb)
}

func (pk *DilithiumPublicKey) Equals(k crypto.Key) bool {
	return basicEquals(pk, k)
}

func (pk *DilithiumPublicKey) Verify(data, sigBytes []byte) (bool, error) {
	h := sha256.New()
	h.Write(data)
	hashedMessage := h.Sum(nil)

	var pkSized [dilithium.PKSizePacked]uint8
	copy(pkSized[:], pk.pb.Pk)

	return reflect.DeepEqual(dilithium.Open(sigBytes, &pkSized), hashedMessage), nil
}

func basicEquals(k1, k2 crypto.Key) bool {
	if k1.Type() != k2.Type() {
		return false
	}

	a, err := k1.Raw()
	if err != nil {
		return false
	}
	b, err := k2.Raw()
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

func UnmarshalDilithiumPublicKey(b []byte) (crypto.PubKey, error) {
	pbData := &protos.DilithiumPublicKey{}
	err := proto.Unmarshal(b, pbData)
	if err != nil {
		return nil, err
	}
	d := &DilithiumPublicKey{
		pb: pbData,
	}
	return d, err
}

func UnmarshalDilithiumPrivateKey(b []byte) (crypto.PrivKey, error) {
	pbData := &protos.DilithiumKeys{}
	err := proto.Unmarshal(b, pbData)
	if err != nil {
		return nil, err
	}
	d := &DilithiumPrivateKey{
		pb: pbData,
	}
	return d, err
}
