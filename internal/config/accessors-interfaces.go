package config

import (
	"context"
	"errors"
	"time"
)

const (
	//NoneType none value
	NoneType ValueType = iota

	//BoolType bool value
	BoolType

	//IntType int value
	IntType

	//UIntType unsigned int value
	UIntType

	//StringType string value
	StringType

	//TimeType date time value
	TimeType

	//DurationType time duration value
	DurationType

	//FloatType float point value
	FloatType
)

var (
	ErrNotFound = errors.New("not found") //nolint
)

type (
	//ValueType value type ID
	ValueType int

	//Value abstract value
	Value interface {
		Is() ValueType
	}

	//Bool bool value reader
	Bool interface {
		Value
		Must(ctx context.Context) bool
		Maybe(ctx context.Context) (bool, error)
	}

	//Int int value reader
	Int interface {
		Value
		Must(ctx context.Context) int
		Maybe(ctx context.Context) (int, error)
	}

	//UInt unsigned int value reader
	UInt interface {
		Value
		Must(ctx context.Context) uint
		Maybe(ctx context.Context) (uint, error)
	}

	//String string value reader
	String interface {
		Value
		Must(ctx context.Context) string
		Maybe(ctx context.Context) (string, error)
	}

	//Time date time value readr
	Time interface {
		Value
		Must(ctx context.Context) time.Time
		Maybe(ctx context.Context) (time.Time, error)
	}

	//Duration time duration value reader
	Duration interface {
		Value
		Must(ctx context.Context) time.Duration
		Maybe(ctx context.Context) (time.Duration, error)
	}

	//Float float point value reader
	Float interface {
		Value
		Must(ctx context.Context) float64
		Maybe(ctx context.Context) (float64, error)
	}
)
