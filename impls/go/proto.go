package main

import (
	"math"
	"strconv"
	"strings"
)

type field struct {
	name   string
	kind   byte
	many   bool
	nested schema
}
type schema map[uint64]field

var instructionSchema = schema{1: {"programIdIndex", 'v', false, nil}, 2: {"accounts", 'b', false, nil}, 3: {"data", 'b', false, nil}, 4: {"stackHeight", 'v', false, nil}}
var innerSchema = schema{1: {"index", 'v', false, nil}, 2: {"instructions", 'm', true, instructionSchema}}
var amountSchema = schema{1: {"uiAmount", 'd', false, nil}, 2: {"decimals", 'v', false, nil}, 3: {"amount", 's', false, nil}, 4: {"uiAmountString", 's', false, nil}}
var tokenSchema = schema{1: {"accountIndex", 'v', false, nil}, 2: {"mint", 's', false, nil}, 3: {"uiTokenAmount", 'm', false, amountSchema}, 4: {"owner", 's', false, nil}, 5: {"programId", 's', false, nil}}
var rewardSchema = schema{1: {"pubkey", 's', false, nil}, 2: {"lamports", 'v', false, nil}, 3: {"postBalance", 'v', false, nil}, 4: {"rewardType", 'v', false, nil}, 5: {"commission", 's', false, nil}, 6: {"commissionBps", 's', false, nil}}
var rewardsSchema = schema{1: {"rewards", 'm', true, rewardSchema}, 2: {"partitions", 'm', false, schema{1: {"count", 'v', false, nil}}}}
var metaSchema = schema{
	1: {"error", 'm', false, schema{1: {"bytes", 'b', false, nil}}},
	2: {"fee", 'v', false, nil}, 3: {"preBalances", 'v', true, nil}, 4: {"postBalances", 'v', true, nil},
	5: {"innerInstructions", 'm', true, innerSchema}, 6: {"logMessages", 's', true, nil},
	7: {"preTokenBalances", 'm', true, tokenSchema}, 8: {"postTokenBalances", 'm', true, tokenSchema},
	9: {"rewards", 'm', true, rewardSchema}, 10: {"innerInstructionsNone", 'v', false, nil},
	11: {"logMessagesNone", 'v', false, nil}, 12: {"loadedWritable", 'b', true, nil}, 13: {"loadedReadonly", 'b', true, nil},
	14: {"returnData", 'm', false, schema{1: {"programId", 'b', false, nil}, 2: {"data", 'b', false, nil}}},
	15: {"returnDataNone", 'v', false, nil}, 16: {"computeUnitsConsumed", 'v', false, nil}, 17: {"costUnits", 'v', false, nil},
}

func protoKey(r *reader) (uint64, uint64) {
	key := r.varint()
	need(key >= 8 && key <= math.MaxUint32, "invalid protobuf key")
	return key >> 3, key & 7
}
func skipProto(r *reader, tag, wire uint64, depth int) {
	switch wire {
	case 0:
		r.varint()
	case 1:
		r.take(8)
	case 2:
		r.sized(r.varint())
	case 3:
		need(depth < 100, "protobuf group depth limit")
		for {
			f, w := protoKey(r)
			if w == 4 {
				need(f == tag, "protobuf group mismatch")
				break
			}
			skipProto(r, f, w, depth+1)
		}
	case 5:
		r.take(4)
	default:
		panic(decodeError("invalid protobuf wire type"))
	}
}
func parseProto(data []byte, fields schema, result obj) obj {
	if result == nil {
		result = make(obj)
	}
	r := reader{data}
	for len(r.left) > 0 {
		tag, wire := protoKey(&r)
		f, ok := fields[tag]
		if !ok {
			skipProto(&r, tag, wire, 0)
			continue
		}
		if f.many && f.kind == 'v' && wire == 2 {
			packed := reader{r.sized(r.varint())}
			values, _ := result[f.name].([]any)
			for len(packed.left) > 0 {
				values = append(values, packed.varint())
			}
			result[f.name] = values
			continue
		}
		var value any
		switch f.kind {
		case 'v':
			need(wire == 0, "wrong protobuf varint wire type")
			value = r.varint()
		case 'd':
			need(wire == 1, "wrong protobuf double wire type")
			value = r.f64()
		default:
			need(wire == 2, "wrong protobuf bytes wire type")
			p := r.sized(r.varint())
			switch f.kind {
			case 's':
				value = validText(p)
			case 'b':
				value = p
			case 'm':
				var existing obj
				if !f.many {
					existing, _ = result[f.name].(obj)
				}
				value = parseProto(p, f.nested, existing)
			}
		}
		if f.many {
			values, _ := result[f.name].([]any)
			result[f.name] = append(values, value)
		} else {
			result[f.name] = value
		}
	}
	return result
}
func num(v any) uint64 { n, _ := v.(uint64); return n }
func str(v any) string { s, _ := v.(string); return s }
func mapValues[T any](v any, fn func(any) T) []T {
	values := array(v)
	out := make([]T, len(values))
	for i, p := range values {
		out[i] = fn(p)
	}
	return out
}
func protoReward(v any) obj {
	m := v.(obj)
	var kind, commission any
	if n := uint32(num(m["rewardType"])); n >= 1 && n <= 4 {
		kind = rewardTypes[n-1]
	}
	if n, err := strconv.ParseUint(strings.TrimPrefix(str(m["commission"]), "+"), 10, 8); err == nil {
		commission = n
	} else if n, err := strconv.ParseUint(strings.TrimPrefix(str(m["commissionBps"]), "+"), 10, 16); err == nil && n/100 <= 255 {
		commission = n / 100
	}
	return reward(str(m["pubkey"]), int64(num(m["lamports"])), num(m["postBalance"]), kind, commission)
}
func protoRewards(m obj) obj {
	returnValue := obj{"rewards": mapValues(m["rewards"], protoReward)}
	if p, ok := m["partitions"].(obj); ok {
		returnValue["numRewardPartitions"] = num(p["count"])
	}
	return returnValue
}
func protoToken(v any) obj {
	m := v.(obj)
	a, _ := m["uiTokenAmount"].(obj)
	var ui any
	if f, _ := a["uiAmount"].(float64); math.Abs(f) > 0x1p-52 {
		ui = finite(f)
	}
	return tokenBalance(byte(num(m["accountIndex"])), str(m["mint"]), ui, byte(num(a["decimals"])), str(a["amount"]), str(a["uiAmountString"]), str(m["owner"]), str(m["programId"]))
}
func protoMeta(m obj) obj {
	result := emptyMeta()
	if v, ok := m["error"].(obj); ok {
		result["err"] = transactionError(&reader{bytesOf(v["bytes"])})
	}
	result["fee"] = num(m["fee"])
	for _, n := range []string{"preBalances", "postBalances"} {
		result[n] = mapValues(m[n], num)
	}
	if num(m["innerInstructionsNone"]) == 0 {
		result["innerInstructions"] = mapValues(m["innerInstructions"], func(v any) innerGroup {
			group := v.(obj)
			return innerGroup{byte(num(group["index"])), mapValues(group["instructions"], func(v any) instruction {
				ix := v.(obj)
				var stack any
				if n, ok := ix["stackHeight"].(uint64); ok {
					stack = uint32(n)
				}
				return instruction{byte(num(ix["programIdIndex"])), bytesOf(ix["accounts"]), bytesOf(ix["data"]), stack}
			})}
		})
	}
	if num(m["logMessagesNone"]) == 0 {
		result["logMessages"] = mapValues(m["logMessages"], str)
	}
	for _, n := range []string{"preTokenBalances", "postTokenBalances"} {
		result[n] = mapValues(m[n], protoToken)
	}
	result["rewards"] = mapValues(m["rewards"], protoReward)
	result["loadedAddresses"] = obj{
		"writable": mapValues(m["loadedWritable"], func(v any) string { return pubkey(bytesOf(v)) }),
		"readonly": mapValues(m["loadedReadonly"], func(v any) string { return pubkey(bytesOf(v)) }),
	}
	if r, ok := m["returnData"].(obj); ok && num(m["returnDataNone"]) == 0 {
		result["returnData"] = returnData(bytesOf(r["programId"]), bytesOf(r["data"]))
	}
	for _, n := range []string{"computeUnitsConsumed", "costUnits"} {
		if v, ok := m[n]; ok {
			result[n] = v
		}
	}
	return result
}
