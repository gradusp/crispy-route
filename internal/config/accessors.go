package config

import (
	"context"
	"time"

	"github.com/gradusp/go-platform/logger"
	"github.com/pkg/errors"
	"github.com/spf13/cast"
)

type (
	//ValueNone none value
	ValueNone struct{}

	//ValueBool bool accessor
	ValueBool string

	//ValueInt int accessor
	ValueInt string

	//ValueUInt uint accessor
	ValueUInt string

	//ValueString string accessor
	ValueString string

	//ValueTime time accessor
	ValueTime string

	//ValueDuration duration accessor
	ValueDuration string

	//ValueFloat float accessor
	ValueFloat string
)

//----------------------------------------------- NONE-----------------------------------------------

//Is ...
func (ValueNone) Is() ValueType {
	return NoneType
}

//----------------------------------------------- BOOL-----------------------------------------------

//Is ...
func (v ValueBool) Is() ValueType {
	return BoolType
}

//Must ...
func (v ValueBool) Must(ctx context.Context) bool {
	a, e := v.Maybe(ctx)
	if e != nil {
		logger.Fatal(ctx, e)
	}
	return a
}

//Maybe ...
func (v ValueBool) Maybe(_ context.Context) (bool, error) {
	const api = "config/ValueBool"

	a := configStore().Get(string(v))
	if a == nil {
		return false, errors.Wrapf(ErrNotFound, "%s: key('%v')", api, v)
	}
	x, e := cast.ToBoolE(a)
	return x, errors.Wrapf(e, "%s: from('%s')", api, v)
}

//----------------------------------------------- INT-----------------------------------------------

//Is ...
func (v ValueInt) Is() ValueType {
	return IntType
}

//Must ...
func (v ValueInt) Must(ctx context.Context) int {
	a, e := v.Maybe(ctx)
	if e != nil {
		logger.Fatal(ctx, e)
	}
	return a
}

//Maybe ...
func (v ValueInt) Maybe(_ context.Context) (int, error) {
	const api = "config/ValueInt"

	a := configStore().Get(string(v))
	if a == nil {
		return 0, errors.Wrapf(ErrNotFound, "%s: key('%v')", api, v)
	}
	x, e := cast.ToIntE(a)
	return x, errors.Wrapf(e, "%s: from('%s')", api, v)
}

//----------------------------------------------- UINT-----------------------------------------------

//Is ...
func (v ValueUInt) Is() ValueType {
	return UIntType
}

//Must ...
func (v ValueUInt) Must(ctx context.Context) uint {
	a, e := v.Maybe(ctx)
	if e != nil {
		logger.Fatal(ctx, e)
	}
	return a
}

//Maybe ...
func (v ValueUInt) Maybe(_ context.Context) (uint, error) {
	const api = "config/ValueUInt"

	a := configStore().Get(string(v))
	if a == nil {
		return 0, errors.Wrapf(ErrNotFound, "%s: key('%v')", api, v)
	}
	x, e := cast.ToUintE(a)
	return x, errors.Wrapf(e, "%s: from('%s')", api, v)
}

//----------------------------------------------- STRING-----------------------------------------------

//Is ...
func (v ValueString) Is() ValueType {
	return StringType
}

//Must ...
func (v ValueString) Must(ctx context.Context) string {
	a, e := v.Maybe(ctx)
	if e != nil {
		logger.Fatal(ctx, e)
	}
	return a
}

//Maybe ...
func (v ValueString) Maybe(_ context.Context) (string, error) {
	const api = "config/ValueString"

	a := configStore().Get(string(v))
	if a == nil {
		return "", errors.Wrapf(ErrNotFound, "%s: key('%v')", api, v)
	}
	x, e := cast.ToStringE(a)
	return x, errors.Wrapf(e, "%s: from('%s')", api, v)
}

//----------------------------------------------- TIME-----------------------------------------------

//Is ,,,
func (v ValueTime) Is() ValueType {
	return TimeType
}

//Must ...
func (v ValueTime) Must(ctx context.Context) time.Time {
	a, e := v.Maybe(ctx)
	if e != nil {
		logger.Fatal(ctx, e)
	}
	return a
}

//Maybe ...
func (v ValueTime) Maybe(_ context.Context) (time.Time, error) {
	const api = "config/ValueTime"

	a := configStore().Get(string(v))
	if a == nil {
		return time.Time{}, errors.Wrapf(ErrNotFound, "%s: key('%v')", api, v)
	}
	x, e := cast.ToTimeE(a)
	return x, errors.Wrapf(e, "%s: from('%s')", api, v)
}

//----------------------------------------------- DURATION-----------------------------------------------

//Is ...
func (v ValueDuration) Is() ValueType {
	return DurationType
}

//Must ...
func (v ValueDuration) Must(ctx context.Context) time.Duration {
	a, e := v.Maybe(ctx)
	if e != nil {
		logger.Fatal(ctx, e)
	}
	return a
}

//Maybe ...
func (v ValueDuration) Maybe(_ context.Context) (time.Duration, error) {
	const api = "config/ValueDuration"

	a := configStore().Get(string(v))
	if a == nil {
		return 0, errors.Wrapf(ErrNotFound, "%s: key('%v')", api, v)
	}
	x, e := cast.ToDurationE(a)
	return x, errors.Wrapf(e, "%s: from('%s')", api, v)
}

//----------------------------------------------- FLOAT-----------------------------------------------

//Is ...
func (v ValueFloat) Is() ValueType {
	return FloatType
}

//Must ,,,
func (v ValueFloat) Must(ctx context.Context) float64 {
	a, e := v.Maybe(ctx)
	if e != nil {
		logger.Fatal(ctx, e)
	}
	return a
}

//Maybe ...
func (v ValueFloat) Maybe(_ context.Context) (float64, error) {
	const api = "config/ValueFloat"

	a := configStore().Get(string(v))
	if a == nil {
		return 0, errors.Wrapf(ErrNotFound, "%s: key('%v')", api, v)
	}
	x, e := cast.ToFloat64E(a)
	return x, errors.Wrapf(e, "%s: from('%s')", api, v)
}
