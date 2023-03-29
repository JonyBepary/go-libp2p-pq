package crypto

import (
	pb "github.com/JonyBepary/go-libp2p-pq/core/crypto/pb"
)

const (
	LATTICE = iota
)

var extendedKeyTypes = []int{
	LATTICE,
}

var isLoaded bool

var mapExtendedKeyTypes = map[int]pb.KeyType{
	// This will be filled when LoadAllExtendedKeyTypes are called
}

func LoadAllExtendedKeyTypes() {
	if isLoaded {
		return
	}
	keyLen := pb.KeyType(len(KeyTypes))
	for _, data := range extendedKeyTypes {
		absoluteExtendedKey := keyLen + pb.KeyType(data)
		PubKeyUnmarshallers[absoluteExtendedKey] = UnmarshalDilithiumPublicKey
		PrivKeyUnmarshallers[absoluteExtendedKey] = UnmarshalDilithiumPrivateKey
		mapExtendedKeyTypes[LATTICE] = absoluteExtendedKey
		keyLen++
	}
	isLoaded = true
}
