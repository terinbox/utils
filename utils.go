package utils

import (
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"html"
	"io"
	"math/rand"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"github.com/oklog/ulid/v2"
)

type ulidInit struct {
	t  time.Time
	en *ulid.MonotonicEntropy
}

var ulidPool = sync.Pool{
	New: func() interface{} {
		t := time.Now()
		return &ulidInit{
			t:  t,
			en: ulid.Monotonic(rand.New(rand.NewSource(time.Now().UnixNano())), 0),
		}
	},
}

// Generates a ULID as described at: "github.com/oklog/ulid/v2"
// Panics on failure
func ULID() string {
	ui, ok := ulidPool.Get().(*ulidInit)
	if !ok {
		ulidPool.Put(ui)
		panic(WrapErr(fmt.Errorf("pool didn't return a MonotonicEntropy")))
	}
	ul, err := ulid.New(ulid.Timestamp(ui.t), ui.en)
	if err != nil {
		ulidPool.Put(ui)
		panic(WrapErr(err, "ulid.new failed"))
	}
	ulidPool.Put(ui)
	return ul.String()
}

// Wraps the given error string with a prefix of
// Function Name -> [msgs[0] -> msgs[1] -> ... msgs[i]] -> err
func WrapErr(err error, msgs ...string) error {
	pc := make([]uintptr, 15)
	n := runtime.Callers(2, pc)
	frames := runtime.CallersFrames(pc[:n])
	frame, _ := frames.Next()
	src := frame.Function
	s := strings.Join(append([]string{src}, msgs...), " -> ")
	return fmt.Errorf("%s -> %s", s, err.Error())
}

// Random Numbers and String
// Based on the amazing SO answer: https://stackoverflow.com/a/31832326/2013671
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

// Generates a random string of length `n` from characters given in `letters`
func RandomFromBytes(n int, letters []byte) string {
	src := rand.NewSource(time.Now().UnixNano())
	sb := strings.Builder{}
	sb.Grow(n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letters) {
			sb.WriteByte(letters[idx])
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return sb.String()
}

// Generates a random string of length `n` consisting of characters [a-z]
func RandomString(n int) string {
	return RandomFromBytes(n, []byte("abcdefghijklmnopqrstuvwxyz"))
}

// Generates a string of length `n` consisting only of characters [0-9]
func RandomNumbers(n int) string {
	return RandomFromBytes(n, []byte("0123456789"))
}

func StringPtr(s string) *string {
	return &s
}

func IntPtr(i int) *int {
	return &i
}

func Int8Ptr(i int8) *int8 {
	return &i
}

func Int16Ptr(i int16) *int16 {
	return &i
}

func Int32Ptr(i int32) *int32 {
	return &i
}

func Int64Ptr(i int64) *int64 {
	return &i
}

func UintPtr(u uint) *uint {
	return &u
}

func Uint8Ptr(u uint8) *uint8 {
	return &u
}

func Uint16Ptr(u uint16) *uint16 {
	return &u
}

func Uint32Ptr(u uint32) *uint32 {
	return &u
}

func Uint64Ptr(u uint64) *uint64 {
	return &u
}

func Float32Ptr(f float32) *float32 {
	return &f
}

func Float64Ptr(f float64) *float64 {
	return &f
}

func BoolPtr(v bool) *bool {
	return &v
}

// Generates a fnv 64 hash
func GenHash64a(txt []byte) string {
	h := fnv.New64a()
	h.Write(txt)
	return hex.EncodeToString(h.Sum(nil))
}

// Generates a fnv 128 hash
func GenHash128a(txt []byte) string {
	h := fnv.New128a()
	h.Write(txt)
	return hex.EncodeToString(h.Sum(nil))
}

// Generates fnv 64 hash of time.Now().UnixNano()
func TimeHash64a() string {
	return GenHash64a([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
}

// Generates 128 fnv hash of time.Now().UnixNano()
func TimeHash128a() string {
	return GenHash128a([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
}

// Returns a UUID v4 string
// Panics if failed to generate. Uses `github.com/google/uuid`
func UUID() string {
	u, err := uuid.NewUUID()
	if err != nil {
		panic(WrapErr(err, "gen failed"))
	}
	return u.String()
}

// Obfuscates email IDs, phones, names
func PartialObfuscate(s string) string {
	len := len(s)
	res := ""

	for i, c := range s {
		if i <= 1 || i >= len-3 || string(c) == "@" {
			res += string(c)
			continue
		}
		res += "*"
	}
	return res
}

// Sanitizes all string and string pointer types in a struct for XSS
// Given any struct `s` - accepts reflect.Value(&s)
func XSSSanitizeStruct(v reflect.Value) {
	if v.Kind() != reflect.Ptr {
		return
	}
	value := v.Elem()
	if value.Kind() != reflect.Struct {
		return
	}

	dummystr := ""
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if field.Type() == reflect.TypeOf("") {
			str := field.Interface().(string)
			field.SetString(html.EscapeString(str))
		}

		if field.Type() == reflect.TypeOf(&dummystr) {
			str := field.Interface().(*string)
			s := html.EscapeString(*str)
			field.Set(reflect.ValueOf(&s))
		}
	}
}

// Trims all string type and values in string pointer in a struct.
// Given a struct `s` - accepts reflect.Value(&s)
func TrimStruct(v reflect.Value) {
	if v.Kind() != reflect.Ptr {
		return
	}
	value := v.Elem()
	if value.Kind() != reflect.Struct {
		return
	}

	dummystr := ""
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if field.Type() == reflect.TypeOf("") {
			str := field.Interface().(string)
			field.SetString(strings.Trim(str, " "))
		}

		if field.Type() == reflect.TypeOf(&dummystr) {
			str := field.Interface().(*string)
			s := strings.Trim(*str, " ")
			field.Set(reflect.ValueOf(&s))
		}
	}
}

// Get an int64 from any integer parading as an interface
func GetInt64(v interface{}) (int64, bool) {
	switch reflect.TypeOf(v).Kind() {
	case reflect.Int:
		d, _ := v.(int)
		return int64(d), true
	case reflect.Int8:
		d, _ := v.(int8)
		return int64(d), true
	case reflect.Int16:
		d, _ := v.(int16)
		return int64(d), true
	case reflect.Int32:
		d, _ := v.(int32)
		return int64(d), true
	case reflect.Int64:
		d, _ := v.(int64)
		return d, true
	case reflect.Uint:
		d, _ := v.(uint)
		return int64(d), true
	case reflect.Uint8:
		d, _ := v.(uint8)
		return int64(d), true
	case reflect.Uint16:
		d, _ := v.(uint16)
		return int64(d), true
	case reflect.Uint32:
		d, _ := v.(uint32)
		return int64(d), true
	case reflect.Uint64:
		d, _ := v.(uint64)
		return int64(d), true
	case reflect.Float32:
		d, _ := v.(float32)
		return int64(d), true
	case reflect.Float64:
		d, _ := v.(float64)
		return int64(d), true
	}
	return 0, false
}

var zstdEncPool = sync.Pool{
	New: func() interface{} {
		enc, err := zstd.NewWriter(nil)
		if err != nil {
			panic(err.Error())
		}
		return enc
	},
}

// Get bytes provided in `in`, compressed in `out`
// Uses: "github.com/klauspost/compress/zstd"
func Compress(in io.Reader, out io.Writer) error {
	e := zstdEncPool.Get()
	enc, ok := e.(*zstd.Encoder)
	if !ok {
		return WrapErr(fmt.Errorf("pool did not return encoder"))
	}
	enc.Reset(out)
	if _, err := io.Copy(enc, in); err != nil {
		enc.Close()
		return WrapErr(err, "io.Copy failed")
	}
	if err := enc.Close(); err != nil {
		return WrapErr(err, "encoder.Close failed")
	}
	return nil
}

var zstdDecPool = sync.Pool{
	New: func() interface{} {
		d, err := zstd.NewReader(nil)
		if err != nil {
			panic(err.Error())
		}
		return d
	},
}

// Provide bytes pre-compressed using zstd in `in` and get them
// decompressed in `out`
// Uses: "github.com/klauspost/compress/zstd"
func Decompress(in io.Reader, out io.Writer) error {
	dec := zstdDecPool.Get()
	d, ok := dec.(*zstd.Decoder)
	if !ok {
		return WrapErr(fmt.Errorf("pool didn't return decoder"))
	}
	d.Reset(in)
	defer d.Close()

	// Copy content...
	if _, err := io.Copy(out, d); err != nil {
		return WrapErr(err, "io.Copy failed")
	}
	return nil
}
