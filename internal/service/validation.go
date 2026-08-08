package service

import (
	"fmt"
	"math"
	"time"
)

const (
	DefaultStepUpTTL = 5 * time.Minute
	MaxStepUpTTL     = 24 * time.Hour
	DefaultInviteTTL = 24 * time.Hour
)

// DurationFromParts converts wire duration fields without allowing int64
// nanosecond overflow. Semantic defaults and limits stay in their use cases.
func DurationFromParts(seconds int64, nanos int32) (time.Duration, error) {
	if nanos < -999999999 || nanos > 999999999 || (seconds > 0 && nanos < 0) || (seconds < 0 && nanos > 0) {
		return 0, fmt.Errorf("%w: invalid duration", ErrInvalidArgument)
	}
	const nanosPerSecond = int64(time.Second)
	maxSeconds := int64(math.MaxInt64) / nanosPerSecond
	minSeconds := int64(math.MinInt64) / nanosPerSecond
	if seconds > maxSeconds || seconds < minSeconds {
		return 0, fmt.Errorf("%w: duration overflows time.Duration", ErrInvalidArgument)
	}
	duration := time.Duration(seconds) * time.Second
	nanoDuration := time.Duration(nanos)
	if nanoDuration > 0 && duration > time.Duration(math.MaxInt64)-nanoDuration {
		return 0, fmt.Errorf("%w: duration overflows time.Duration", ErrInvalidArgument)
	}
	if nanoDuration < 0 && duration < time.Duration(math.MinInt64)-nanoDuration {
		return 0, fmt.Errorf("%w: duration overflows time.Duration", ErrInvalidArgument)
	}
	return duration + nanoDuration, nil
}

func DurationFromSeconds(seconds int64) (time.Duration, error) {
	return DurationFromParts(seconds, 0)
}

func normalizeStepUpTTL(ttl time.Duration) (time.Duration, error) {
	if ttl == 0 {
		return DefaultStepUpTTL, nil
	}
	if ttl < 0 || ttl > MaxStepUpTTL {
		return 0, fmt.Errorf("%w: step-up ttl must be greater than zero and at most 24h", ErrInvalidArgument)
	}
	return ttl, nil
}

func normalizeInviteTTL(ttl time.Duration) (time.Duration, error) {
	if ttl == 0 {
		return DefaultInviteTTL, nil
	}
	if ttl < 0 {
		return 0, fmt.Errorf("%w: invite ttl must not be negative", ErrInvalidArgument)
	}
	return ttl, nil
}
