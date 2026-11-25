package main

import (
	"encoding/base64"
	"math"
	"strconv"
	"strings"
)

var instructionErrors = strings.Fields(`GenericError InvalidArgument InvalidInstructionData InvalidAccountData AccountDataTooSmall
InsufficientFunds IncorrectProgramId MissingRequiredSignature AccountAlreadyInitialized
UninitializedAccount UnbalancedInstruction ModifiedProgramId ExternalAccountLamportSpend
ExternalAccountDataModified ReadonlyLamportChange ReadonlyDataModified DuplicateAccountIndex
ExecutableModified RentEpochModified NotEnoughAccountKeys AccountDataSizeChanged
AccountNotExecutable AccountBorrowFailed AccountBorrowOutstanding DuplicateAccountOutOfSync
Custom InvalidError ExecutableDataModified ExecutableLamportChange ExecutableAccountNotRentExempt
UnsupportedProgramId CallDepth MissingAccount ReentrancyNotAllowed MaxSeedLengthExceeded
InvalidSeeds InvalidRealloc ComputationalBudgetExceeded PrivilegeEscalation
ProgramEnvironmentSetupFailure ProgramFailedToComplete ProgramFailedToCompile Immutable
IncorrectAuthority BorshIoError AccountNotRentExempt InvalidAccountOwner ArithmeticOverflow
UnsupportedSysvar IllegalOwner MaxAccountsDataAllocationsExceeded MaxAccountsExceeded
MaxInstructionTraceLengthExceeded BuiltinProgramsMustConsumeComputeUnits`)
var transactionErrors = strings.Fields(`AccountInUse AccountLoadedTwice AccountNotFound ProgramAccountNotFound InsufficientFundsForFee
InvalidAccountForFee AlreadyProcessed BlockhashNotFound InstructionError CallChainTooDeep
MissingSignatureForFee InvalidAccountIndex SignatureFailure InvalidProgramForExecution
SanitizeFailure ClusterMaintenance AccountBorrowOutstanding WouldExceedMaxBlockCostLimit
UnsupportedVersion InvalidWritableAccount WouldExceedMaxAccountCostLimit
WouldExceedAccountDataBlockLimit TooManyAccountLocks AddressLookupTableNotFound
InvalidAddressLookupTableOwner InvalidAddressLookupTableData InvalidAddressLookupTableIndex
InvalidRentPayingAccount WouldExceedMaxVoteCostLimit WouldExceedAccountDataTotalLimit
DuplicateInstruction InsufficientFundsForRent MaxLoadedAccountsDataSizeExceeded
InvalidLoadedAccountsDataSizeLimit ResanitizationNeeded ProgramExecutionTemporarilyRestricted
UnbalancedTransaction ProgramCacheHitMaxLimit CommitCancelled`)

func transactionError(r *reader) any {
	kind := r.u32()
	need(uint64(kind) < uint64(len(transactionErrors)), "unknown TransactionError")
	name := transactionErrors[kind]
	switch kind {
	case 8:
		index, code := r.u8(), r.u32()
		need(uint64(code) < uint64(len(instructionErrors)), "unknown InstructionError")
		var reason any = instructionErrors[code]
		if code == 25 {
			reason = obj{"Custom": r.u32()}
		}
		return obj{name: []any{index, reason}}
	case 30:
		return obj{name: r.u8()}
	case 31, 35:
		return obj{name: obj{"account_index": r.u8()}}
	default:
		return name
	}
}
func emptyMeta() obj {
	return obj{"fee": uint64(0), "preBalances": []uint64{}, "postBalances": []uint64{},
		"loadedAddresses": obj{"writable": []string{}, "readonly": []string{}}}
}
func tokenBalance(index byte, mint string, ui any, decimals byte, amount, display, owner, program string) obj {
	if display == "" {
		n, err := strconv.ParseUint(strings.TrimPrefix(amount, "+"), 10, 64)
		if err != nil {
			n = 0
		}
		display = strconv.FormatUint(n, 10)
		if d := int(decimals); d > 0 {
			if len(display) <= d {
				display = strings.Repeat("0", d+1-len(display)) + display
			}
			split := len(display) - d
			display = strings.TrimSuffix(strings.TrimRight(display[:split]+"."+display[split:], "0"), ".")
		}
	}
	out := obj{"accountIndex": index, "mint": mint, "uiTokenAmount": obj{"uiAmount": ui, "decimals": decimals, "amount": amount, "uiAmountString": display}}
	if owner != "" {
		out["owner"] = owner
	}
	if program != "" {
		out["programId"] = program
	}
	return out
}
func finite(f float64) any {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil
	}
	return f
}
func returnData(program, data []byte) obj {
	return obj{"programId": pubkey(program), "data": []string{base64.StdEncoding.EncodeToString(data), "base64"}}
}

var rewardTypes = []string{"Fee", "Rent", "Staking", "Voting"}

func reward(key string, lamports int64, balance uint64, kind, commission any) obj {
	return obj{"pubkey": key, "lamports": lamports, "postBalance": balance, "rewardType": kind, "commission": commission}
}
func (r *reader) str() string { return validText(r.sized(r.u64())) }
func option[T any](r *reader, next func() T) any {
	tag := r.u8()
	need(tag <= 1, "invalid bincode option")
	if tag == 1 {
		return next()
	}
	return nil
}
func optional[T any](r *reader, next func() T) any {
	if len(r.left) == 0 {
		return nil
	}
	return option(r, next)
}
func vec[T any](r *reader, minSize int, next func() T) []T { return list(r, r.u64(), minSize, next) }

func storedReward(r *reader, extended bool) obj {
	key, lamports := r.str(), int64(r.u64())
	var balance uint64
	var kind, commission any
	if !extended || len(r.left) > 0 {
		balance = r.u64()
	}
	if !extended || len(r.left) > 0 {
		kind = option(r, func() string {
			v := r.u32()
			need(uint64(v) < uint64(len(rewardTypes)), "invalid bincode RewardType")
			return rewardTypes[v]
		})
	}
	if extended {
		commission = optional(r, r.u8)
	}
	return reward(key, lamports, balance, kind, commission)
}
func storedToken(r *reader, layout int) obj {
	index, mint, ui, decimals, amount := r.u8(), r.str(), finite(r.f64()), r.u8(), r.str()
	var owner, program string
	if layout >= 2 && len(r.left) > 0 {
		owner = r.str()
	}
	if layout >= 3 && len(r.left) > 0 {
		program = r.str()
	}
	return tokenBalance(index, mint, ui, decimals, amount, "", owner, program)
}
func storedMeta(r *reader, legacy bool, layout int) obj {
	status := r.u32()
	need(status <= 1, "invalid bincode result")
	m := emptyMeta()
	if status == 1 {
		m["err"] = transactionError(r)
	}
	m["fee"] = r.u64()
	m["preBalances"] = vec(r, 8, r.u64)
	m["postBalances"] = vec(r, 8, r.u64)
	m["innerInstructions"] = optional(r, func() []innerGroup {
		return vec(r, 9, func() innerGroup {
			index := r.u8()
			instructions := vec(r, 3, func() instruction {
				ix := compileInstruction(r, nil)
				if !legacy {
					ix.stack = option(r, r.u32)
				}
				return ix
			})
			return innerGroup{index, instructions}
		})
	})
	m["logMessages"] = optional(r, func() []string { return vec(r, 8, r.str) })
	tokens := func() []obj { return vec(r, 26, func() obj { return storedToken(r, layout) }) }
	m["preTokenBalances"] = optional(r, tokens)
	m["postTokenBalances"] = optional(r, tokens)
	m["rewards"] = optional(r, func() []obj { return vec(r, 16, func() obj { return storedReward(r, true) }) })
	m["returnData"] = optional(r, func() obj { return returnData(r.take(32), r.sized(r.u64())) })
	m["computeUnitsConsumed"] = optional(r, r.u64)
	m["costUnits"] = optional(r, r.u64)
	return m
}
func bincodeMeta(data []byte) obj {
	for i := 0; i < 4; i++ {
		r := reader{data}
		layout := i
		if layout == 0 {
			layout = 3
		}
		if m, failure := attempt(func() obj { return storedMeta(&r, i != 0, layout) }); failure == "" && len(r.left) == 0 {
			return m
		}
	}
	r := reader{data}
	return storedMeta(&r, false, 3)
}
func bincodeRewards(data []byte) obj {
	decode := func(r *reader, extended bool) obj {
		return obj{"rewards": vec(r, 16, func() obj { return storedReward(r, extended) })}
	}
	for _, extended := range []bool{true, false} {
		r := reader{data}
		if m, failure := attempt(func() obj { return decode(&r, extended) }); failure == "" && len(r.left) == 0 {
			return m
		}
	}
	r := reader{data}
	return decode(&r, true)
}

const epochSlots = 432000
const bincodeCutoff = 157 * epochSlots

func decodePayload(slot uint64, p []byte, rewards bool) obj {
	schema, convert, legacy := metaSchema, protoMeta, bincodeMeta
	if rewards {
		schema, convert, legacy = rewardsSchema, protoRewards, bincodeRewards
	}
	if slot < bincodeCutoff {
		if v, failure := attempt(func() obj { return legacy(p) }); failure == "" {
			return v
		}
		return convert(parseProto(p, schema, nil))
	}
	if v, failure := attempt(func() obj { return parseProto(p, schema, nil) }); failure == "" {
		return convert(v)
	}
	return legacy(p)
}
func decodedFrame(slot uint64, p []byte, rewards bool) obj {
	if len(p) == 0 {
		if rewards {
			return obj{"rewards": []obj{}}
		}
		return nil
	}
	decode := func(p []byte) obj { return decodePayload(slot, p, rewards) }
	if len(p) >= 4 && p[0] == 0x28 && p[1] == 0xb5 && p[2] == 0x2f && p[3] == 0xfd {
		if plain, failure := attempt(func() []byte { return decompressZstd(p) }); failure == "" {
			return decode(plain)
		}
		return decode(p)
	}
	v, firstFailure := attempt(func() obj { return decode(p) })
	if firstFailure == "" {
		return v
	}
	if plain, failure := attempt(func() []byte { return decompressZstd(p) }); failure == "" {
		return decode(plain)
	}
	panic(firstFailure)
}
