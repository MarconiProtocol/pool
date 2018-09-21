package cryptonightbridge

import (
	"math/big"

	"github.com/ethereum/ethash"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"gitlab.neji.vm.tc/marconi/marconi-cryptonight"
)

var twoTo256 = new(big.Int).Exp(common.Big2, common.Big256, nil)

type CryptoNightHash struct {}

func New() *CryptoNightHash {
	return &CryptoNightHash{}
}

// based on https://github.com/ethereum/ethash/blob/f5f0a8b1962544d2b6f40df8e4b0d9a32faf8f8e/ethash.go#L128
func (hash *CryptoNightHash) Verify(block ethash.Block) bool {
	difficulty := block.Difficulty()

	/* Cannot happen if block header diff is validated prior to PoW, but can
		 happen if PoW is checked first due to parallel PoW checking.
		 We could check the minimum valid difficulty but for SoC we avoid (duplicating)
	   Ethereum protocol consensus rules here which are not in scope of Ethash
	*/
	if difficulty.Cmp(common.Big0) == 0 {
		log.Debug("invalid block difficulty")
		return false
	}

	digestBytes, resultBytes := cryptonight.HashVariant4ForEthereumHeader(block.HashNoNonce().Bytes(), block.Nonce(), block.NumberU64())
	mixDigest := common.BytesToHash(digestBytes)
	result := common.BytesToHash(resultBytes)

	// avoid mixdigest malleability as it's not included in a block's "hashNononce"
	if block.MixDigest() != mixDigest {
		return false
	}

	// The actual check.
	target := new(big.Int).Div(twoTo256, difficulty)
	return result.Big().Cmp(target) <= 0
}
