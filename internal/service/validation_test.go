package service

import (
	"errors"
	"math"
	"testing"
	"time"
)

func TestDurationConversionRejectsOverflow(t *testing.T) {
	maxSeconds := int64(math.MaxInt64) / int64(time.Second)
	got, err := DurationFromSeconds(maxSeconds)
	if err != nil || got <= 0 {
		t.Fatalf("max safe seconds: duration=%s err=%v", got, err)
	}
	if _, err := DurationFromSeconds(maxSeconds + 1); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected overflow error, got %v", err)
	}
	if _, err := DurationFromParts(maxSeconds, 999999999); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected nanosecond overflow error, got %v", err)
	}
}

func TestStepUpTTLContract(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want time.Duration
		ok   bool
	}{
		{"default", 0, DefaultStepUpTTL, true},
		{"negative", -time.Nanosecond, 0, false},
		{"small_positive", time.Nanosecond, time.Nanosecond, true},
		{"maximum", MaxStepUpTTL, MaxStepUpTTL, true},
		{"over_maximum", MaxStepUpTTL + time.Nanosecond, 0, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeStepUpTTL(test.in)
			if test.ok && (err != nil || got != test.want) {
				t.Fatalf("got %s, %v; want %s", got, err, test.want)
			}
			if !test.ok && !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("expected invalid argument, got %v", err)
			}
		})
	}
}

func TestInviteTTLContract(t *testing.T) {
	got, err := normalizeInviteTTL(0)
	if err != nil || got != DefaultInviteTTL {
		t.Fatalf("default ttl: got %s, %v", got, err)
	}
	if _, err := normalizeInviteTTL(-time.Nanosecond); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("negative ttl: %v", err)
	}
	if got, err := normalizeInviteTTL(time.Nanosecond); err != nil || got != time.Nanosecond {
		t.Fatalf("positive ttl: got %s, %v", got, err)
	}
}
