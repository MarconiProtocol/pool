package proxy

import (
	"log"
	"math/big"
	"strconv"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"

	"git.marconi.org/marconiprotocol/pool/rpc"
	"git.marconi.org/marconiprotocol/pool/util"
)

const maxBacklog = 3

// Counters for tracking some RPC stats.
var numTimesRpcsAgreed int = 0
var numTimesRpcsSent int = 0

type heightDiffPair struct {
	diff   *big.Int
	height uint64
}

type BlockTemplate struct {
	sync.RWMutex
	Header               string
	Seed                 string
	Target               string
	Difficulty           *big.Int
	Height               uint64
	GetPendingBlockCache *rpc.GetBlockReplyPart
	nonces               map[string]bool
	headers              map[string]heightDiffPair
}

type Block struct {
	difficulty  *big.Int
	hashNoNonce common.Hash
	nonce       uint64
	mixDigest   common.Hash
	number      uint64
}

func (b Block) Difficulty() *big.Int     { return b.difficulty }
func (b Block) HashNoNonce() common.Hash { return b.hashNoNonce }
func (b Block) Nonce() uint64            { return b.nonce }
func (b Block) MixDigest() common.Hash   { return b.mixDigest }
func (b Block) NumberU64() uint64        { return b.number }

func (s *ProxyServer) fetchBlockTemplate() {
	rpc := s.rpc()
	s.blockWriteMutex.Lock()
	defer s.blockWriteMutex.Unlock()
	t := s.currentBlockTemplate()
	pendingReply, height, diff, err := s.fetchPendingBlock()
	if err != nil {
		log.Printf("Error while refreshing pending block on %s: %s", rpc.Name, err)
		return
	}
	reply, err := rpc.GetWork()
	if err != nil {
		log.Printf("Error while refreshing block template on %s: %s", rpc.Name, err)
		return
	}

	// To work around a race condition that happens pretty rarely, we
	// need to check whether the height returned by the
	// GetWorkWithExtraData RPC is the same as the height returned by
	// the GetPendingBlock RPC (which ends up getting called through the
	// fetchPendingBlock function above). Most of the time the height
	// matches, in which case we can proceed as normal. But sometimes
	// the height doesn't match, simply because the first RPC occurred
	// slightly before geth updated to the next block, and the second
	// RPC slightly after. In such a case we can't proceed as normal,
	// because miners will get stuck trying to find nonces at a block
	// height which doesn't match with the latest block header returned
	// by GetWorkWithExtraData, so geth will always reject these proofs
	// of work as invalid. This didn't matter prior to CryptonightR
	// because the block height wasn't an input to the proof-of-work
	// hash function. As a simple fix, we just 'return' in a such a case
	// (see below) and wait for the next call to fetchBlockTemplate, at
	// which point the RPCs will be reissued and should have matching
	// responses. The next pair of RPCs get issued quite quickly, since
	// the default polling interval is 120 ms (see blockRefreshInterval
	// in the json config). If for some reason we still see related
	// problems in the future, the best fix is probably to never send
	// the GetPendingBlock RPC, because it looks like all the info it
	// returns can also be derived from the response to
	// GetWorkWithExtraData, e.g. 'difficulty' can be derived from
	// 'target' with a simple conversion.
	height_from_other_rpc, err := strconv.ParseUint(strings.Replace(reply[3], "0x", "", -1), 16, 64)
	if err != nil {
		log.Println("Can't parse height from GetWork RPC")
		return
	}
	numTimesRpcsSent++
	if height_from_other_rpc != height {
		log.Printf("Height mismatch between GetPendingBlock and GetWork RPCs: %d vs %d\n", height, height_from_other_rpc)
		log.Printf("This mismatch is expected to happen on rare occasions. Will ignore these RPC responses and retry the RPCs.\n")
		log.Printf("Total RPCs sent over process lifetime: %d, RPCs with responses that matched: %d\n", numTimesRpcsSent, numTimesRpcsAgreed)
		return;
	}
	numTimesRpcsAgreed++

	// No need to update, we have fresh job
	if t != nil && t.Header == reply[0] {
		return
	}

	pendingReply.Difficulty = util.ToHex(s.config.Proxy.Difficulty)

	newTemplate := BlockTemplate{
		Header:               reply[0],
		Seed:                 reply[1],
		Target:               reply[2],
		Height:               height,
		Difficulty:           big.NewInt(diff),
		GetPendingBlockCache: pendingReply,
		headers:              make(map[string]heightDiffPair),
	}
	// Copy job backlog and add current one
	newTemplate.headers[reply[0]] = heightDiffPair{
		diff:   util.TargetHexToDiff(reply[2]),
		height: height,
	}
	if t != nil {
		for k, v := range t.headers {
			if v.height > height-maxBacklog {
				newTemplate.headers[k] = v
			}
		}
	}
	s.blockTemplate.Store(&newTemplate)
	log.Printf("New block to mine on %s at height %d / %s", rpc.Name, height, reply[0][0:10])

	// Stratum
	if s.config.Proxy.Stratum.Enabled {
		go s.broadcastNewJobs()
	}
}

func (s *ProxyServer) fetchPendingBlock() (*rpc.GetBlockReplyPart, uint64, int64, error) {
	rpc := s.rpc()
	reply, err := rpc.GetPendingBlock()
	if err != nil {
		log.Printf("Error while refreshing pending block on %s: %s", rpc.Name, err)
		return nil, 0, 0, err
	}
	blockNumber, err := strconv.ParseUint(strings.Replace(reply.Number, "0x", "", -1), 16, 64)
	if err != nil {
		log.Println("Can't parse pending block number")
		return nil, 0, 0, err
	}
	blockDiff, err := strconv.ParseInt(strings.Replace(reply.Difficulty, "0x", "", -1), 16, 64)
	if err != nil {
		log.Println("Can't parse pending block difficulty")
		return nil, 0, 0, err
	}
	return reply, blockNumber, blockDiff, nil
}
