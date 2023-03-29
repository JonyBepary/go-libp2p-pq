package crypto

import (
	"crypto/rand"
	"errors"
	"io"

	pb "github.com/JonyBepary/go-libp2p-pq/core/crypto/pb"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
)

type DilithiumPrivateKey struct {
	pb *mode2.PrivateKey
	pk *mode2.PublicKey
}

type DilithiumPublicKey struct {
	pb *mode2.PublicKey
}

func GenerateDilithiumKey(src io.Reader) (PrivKey, PubKey, error) {
	if !isLoaded {
		return nil, nil, errors.New("LoadAllExtendedKeyTypes before using")
	}
	r := rand.Reader

	pubkey, privkey, err := mode2.GenerateKey(r)
	if err != nil {
		return nil, nil, err
	}

	return &DilithiumPrivateKey{
			pb: privkey,
			pk: privkey.Public().(*mode2.PublicKey),
		},
		&DilithiumPublicKey{
			pb: pubkey,
		},
		nil
}

func (sk *DilithiumPrivateKey) Type() pb.KeyType {
	return mapExtendedKeyTypes[LATTICE]
}

func (sk *DilithiumPrivateKey) Bytes() ([]byte, error) {
	return MarshalPrivateKey(sk)
}

func (sk *DilithiumPrivateKey) Raw() ([]byte, error) {
	return sk.Bytes()
}

func (sk *DilithiumPrivateKey) Equals(k Key) bool {
	return sk.Equals(k)
}

func (sk *DilithiumPrivateKey) Sign(data []byte) ([]byte, error) {
	r := rand.Reader

	return sk.pb.Sign(r, data, nil)
}

func (sk *DilithiumPrivateKey) GetPublic() PubKey {

	return &DilithiumPublicKey{
		pb: sk.pk,
	}
}

func (pk *DilithiumPublicKey) Bytes() ([]byte, error) {
	return pk.pb.MarshalBinary()
}

func (pk *DilithiumPublicKey) Type() pb.KeyType {
	return mapExtendedKeyTypes[LATTICE]
}

func (pk *DilithiumPublicKey) Raw() ([]byte, error) {
	return pk.pb.Bytes(), nil
}

func (pk *DilithiumPublicKey) Equals(k Key) bool {
	return pk.pb.Equal(k.(*DilithiumPublicKey).pb)
}

func (pk *DilithiumPublicKey) Verify(data, sigBytes []byte) (bool, error) {
	return mode2.Verify(pk.pb, data, sigBytes), nil
}

func UnmarshalDilithiumPublicKey(b []byte) (PubKey, error) {
	PublicKey := &mode2.PublicKey{}
	err := PublicKey.UnmarshalBinary(b)
	d := &DilithiumPublicKey{
		pb: PublicKey,
	}

	return d, err
}

func UnmarshalDilithiumPrivateKey(b []byte) (PrivKey, error) {
	PrivateKey := &mode2.PrivateKey{}
	err := PrivateKey.UnmarshalBinary(b)
	d := &DilithiumPrivateKey{
		pb: PrivateKey,
		pk: PrivateKey.Public().(*mode2.PublicKey),
	}
	return d, err
}
