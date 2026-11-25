package main

import (
	"encoding/base64"
	"slices"
	"strings"
)

type instruction struct {
	program        byte
	accounts, data []byte
	stack          any
}
type innerGroup struct {
	index        byte
	instructions []instruction
}
type transaction struct {
	v0           bool
	header       [3]byte
	signatures   [][]byte
	keys         []string
	hash         string
	instructions []instruction
	lookups      []obj
	raw          []byte
}

func compileInstruction(r *reader, stack any) instruction {
	return instruction{r.u8(), r.take(r.compact()), r.take(r.compact()), stack}
}
func decodeTransaction(data []byte) transaction {
	r := reader{data}
	tx := transaction{}
	tx.signatures = list(&r, uint64(r.compact()), 64, func() []byte { return r.take(64) })
	prefix := r.u8()
	need(prefix <= 128, "unsupported transaction version")
	tx.v0 = prefix == 128
	if tx.v0 {
		prefix = r.u8()
	}
	tx.header = [3]byte{prefix, r.u8(), r.u8()}
	tx.keys = list(&r, uint64(r.compact()), 32, func() string { return pubkey(r.take(32)) })
	tx.hash = pubkey(r.take(32))
	tx.instructions = list(&r, uint64(r.compact()), 3, func() instruction { return compileInstruction(&r, 1) })
	if tx.v0 {
		tx.lookups = list(&r, uint64(r.compact()), 34, func() obj {
			return obj{"accountKey": pubkey(r.take(32)), "writableIndexes": indexes(r.take(r.compact())), "readonlyIndexes": indexes(r.take(r.compact()))}
		})
	}
	tx.raw = data[:len(data)-len(r.left)]
	return tx
}
func indexes(p []byte) []int {
	a := make([]int, len(p))
	for i, b := range p {
		a[i] = int(b)
	}
	return a
}
func instructionsJSON(ixs []instruction, resolved []string) []obj {
	out := make([]obj, 0, len(ixs))
	for _, ix := range ixs {
		value := obj{"data": base58(ix.data), "stackHeight": ix.stack}
		if resolved == nil {
			value["programIdIndex"] = ix.program
			value["accounts"] = indexes(ix.accounts)
		} else {
			at := func(i byte) string {
				need(int(i) < len(resolved), "instruction account index out of range")
				return resolved[i]
			}
			accounts := make([]string, len(ix.accounts))
			for i, k := range ix.accounts {
				accounts[i] = at(k)
			}
			value["programId"] = at(ix.program)
			value["accounts"] = accounts
		}
		out = append(out, value)
	}
	return out
}

const upgradeableLoader = "BPFLoaderUpgradeab1e11111111111111111111111"

var reserved = func() map[string]bool {
	set := make(map[string]bool)
	for _, key := range strings.Fields(`AddressLookupTab1e1111111111111111111111111   BPFLoader2111111111111111111111111111111111
BPFLoader1111111111111111111111111111111111   BPFLoaderUpgradeab1e11111111111111111111111
ComputeBudget111111111111111111111111111111   Config1111111111111111111111111111111111111
Ed25519SigVerify111111111111111111111111111   Feature111111111111111111111111111111111111
LoaderV411111111111111111111111111111111111   KeccakSecp256k11111111111111111111111111111
Secp256r1SigVerify1111111111111111111111111   StakeConfig11111111111111111111111111111111
Stake11111111111111111111111111111111111111   11111111111111111111111111111111
Vote111111111111111111111111111111111111111   ZkE1Gama1Proof11111111111111111111111111111
ZkTokenProof1111111111111111111111111111111   SysvarC1ock11111111111111111111111111111111
SysvarEpochRewards1111111111111111111111111   SysvarEpochSchedu1e111111111111111111111111
SysvarFees111111111111111111111111111111111   Sysvar1nstructions1111111111111111111111111
SysvarLastRestartS1ot1111111111111111111111   SysvarRecentB1ockHashes11111111111111111111
SysvarRent111111111111111111111111111111111   SysvarRewards111111111111111111111111111111
SysvarS1otHashes111111111111111111111111111   SysvarS1otHistory11111111111111111111111111
SysvarStakeHistory1111111111111111111111111   NativeLoader1111111111111111111111111111111
Sysvar1111111111111111111111111111111111111`) {
		set[key] = true
	}
	return set
}()

func (tx transaction) accounts(meta obj) ([]obj, []string) {
	var writable, readonly []string
	if tx.v0 && meta != nil {
		loaded := meta["loadedAddresses"].(obj)
		writable = loaded["writable"].([]string)
		readonly = loaded["readonly"].([]string)
	}
	keys := slices.Concat(tx.keys, writable, readonly)
	if keys == nil {
		keys = []string{}
	}
	programs := [256]bool{}
	for _, ix := range tx.instructions {
		programs[ix.program] = true
	}
	upgradeable := slices.Contains(keys, upgradeableLoader)
	signers := int(tx.header[0])
	accounts := make([]obj, 0, len(keys))
	for i, key := range keys {
		source := "transaction"
		signer := i < signers
		canWrite := i < len(tx.keys)-int(tx.header[2])
		if signer {
			canWrite = i < signers-int(tx.header[1])
		}
		if i >= len(tx.keys) {
			source = "lookupTable"
			canWrite = i < len(tx.keys)+len(writable)
		}
		canWrite = canWrite && !reserved[key] && (upgradeable || i >= 256 || !programs[i])
		accounts = append(accounts, obj{"pubkey": key, "source": source, "signer": signer, "writable": canWrite})
	}
	return accounts, keys
}
func (tx transaction) json(meta obj, options blockOptions) obj {
	if tx.v0 {
		if !options.version {
			panic(rpcFailure{-32015, "Transaction version (0) requires maxSupportedTransactionVersion: 0"})
		}
		if meta == nil {
			meta = emptyMeta()
		}
	}
	var encoded any
	var resolved []string
	parsed := options.encoding == "jsonParsed"
	accountsOnly := options.details == "accounts"
	switch options.encoding {
	case "base64":
		encoded = []string{base64.StdEncoding.EncodeToString(tx.raw), "base64"}
	case "base58":
		encoded = []string{base58(tx.raw), "base58"}
	default:
		signatures := make([]string, len(tx.signatures))
		for i, p := range tx.signatures {
			signatures[i] = base58(p)
		}
		var keys any = tx.keys
		if parsed || accountsOnly {
			accounts, allKeys := tx.accounts(meta)
			keys = accounts
			if parsed {
				resolved = allKeys
			}
		}
		value := obj{"signatures": signatures}
		if accountsOnly {
			value["accountKeys"] = keys
		} else {
			message := obj{"accountKeys": keys, "recentBlockhash": tx.hash, "instructions": instructionsJSON(tx.instructions, resolved)}
			if !parsed {
				message["header"] = obj{"numRequiredSignatures": tx.header[0], "numReadonlySignedAccounts": tx.header[1], "numReadonlyUnsignedAccounts": tx.header[2]}
			}
			if tx.v0 {
				message["addressTableLookups"] = tx.lookups
			}
			value["message"] = message
		}
		encoded = value
	}
	out := obj{"transaction": encoded, "meta": nil}
	if meta != nil {
		if options.version {
			if tx.v0 {
				out["version"] = 0
			} else {
				out["version"] = "legacy"
			}
		}
		status := obj{"Ok": nil}
		if failure := meta["err"]; failure != nil {
			status = obj{"Err": failure}
		}
		m := obj{"status": status}
		for _, key := range []string{"err", "fee", "preBalances", "postBalances", "preTokenBalances", "postTokenBalances"} {
			m[key] = meta[key]
		}
		if options.rewards {
			m["rewards"] = meta["rewards"]
		} else if !accountsOnly {
			m["rewards"] = nil
		}
		if !accountsOnly {
			m["innerInstructions"] = nil
			if groups, ok := meta["innerInstructions"].([]innerGroup); ok {
				list := make([]obj, 0, len(groups))
				for _, group := range groups {
					list = append(list, obj{"index": group.index, "instructions": instructionsJSON(group.instructions, resolved)})
				}
				m["innerInstructions"] = list
			}
			m["logMessages"] = meta["logMessages"]
			if !parsed {
				m["loadedAddresses"] = meta["loadedAddresses"]
			}
			for _, key := range []string{"returnData", "computeUnitsConsumed", "costUnits"} {
				if v := meta[key]; v != nil {
					m[key] = v
				}
			}
		}
		out["meta"] = m
	}
	return out
}
