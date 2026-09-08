// Package realclientv0 exercises decoded validation and a synthetic preset only.
package realclientv0

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"time"
)

type Config struct {
	Sources      []Source               `json:"sources"`
	FeedCacheDir *string                `json:"feedCacheDir"`
	Unknown      map[string]interface{} `mapstructure:",remain" json:"unknown"`
}
type Source struct {
	Name    *string                `json:"name"`
	Preset  *string                `json:"preset"`
	Trust   *Trust                 `json:"trust"`
	Extract *Extraction            `json:"extract"`
	Scheme  *Extraction            `json:"scheme"`
	Unknown map[string]interface{} `mapstructure:",remain" json:"unknown"`
}
type Trust struct {
	Static       *[]string              `json:"static"`
	Feeds        *[]Feed                `json:"feeds"`
	HeaderIn     *HeaderIn              `json:"headerIn"`
	HostExact    *HostExact             `json:"hostExact"`
	HostSuffixes *HostSuffixes          `json:"hostSuffixes"`
	Unknown      map[string]interface{} `mapstructure:",remain" json:"unknown"`
}
type Feed struct {
	URL             *string                `json:"url"`
	Format          *string                `json:"format"`
	RefreshInterval *string                `json:"refreshInterval"`
	MinEntries      interface{}            `json:"minEntries"`
	Unknown         map[string]interface{} `mapstructure:",remain" json:"unknown"`
}
type Extraction struct {
	Header  *string                `json:"header"`
	Mode    *string                `json:"mode"`
	Unknown map[string]interface{} `mapstructure:",remain" json:"unknown"`
}
type HeaderIn struct {
	Name    *string                `json:"name"`
	Values  *[]string              `json:"values"`
	Unknown map[string]interface{} `mapstructure:",remain" json:"unknown"`
}
type HostExact struct {
	Header  *string                `json:"header"`
	Values  *[]string              `json:"values"`
	Unknown map[string]interface{} `mapstructure:",remain" json:"unknown"`
}
type HostSuffixes struct {
	Header   *string                `json:"header"`
	Suffixes *[]string              `json:"suffixes"`
	Unknown  map[string]interface{} `mapstructure:",remain" json:"unknown"`
}

func CreateConfig() *Config { return &Config{} }

// walk validates only V0's decoded presence/unknown-key/list contract.
func walk(v reflect.Value, path string) error {
	if v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil
		}
		return walk(v.Elem(), path)
	}
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			field := v.Type().Field(i)
			value := v.Field(i)
			if field.Name == "Unknown" {
				if value.Len() > 0 {
					return fmt.Errorf("%s: unknown fields", path)
				}
				continue
			}
			if err := walk(value, path+"."+field.Name); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if !v.IsNil() && v.Len() == 0 {
			return fmt.Errorf("%s: empty list", path)
		}
		for i := 0; i < v.Len(); i++ {
			if err := walk(v.Index(i), path); err != nil {
				return err
			}
		}
	}
	return nil
}
func str(value string) *string { return &value }
func inspect(cfg *Config) (*Config, error) {
	if err := walk(reflect.ValueOf(cfg), "config"); err != nil {
		return nil, err
	}
	// New borrows input. Deep-copy before doing any fixture overlay.
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var effective Config
	if err = json.Unmarshal(data, &effective); err != nil {
		return nil, err
	}
	for i := range effective.Sources {
		source := &effective.Sources[i]
		if source.Preset != nil {
			if *source.Preset != "v0" {
				return nil, fmt.Errorf("unknown fixture preset")
			}
			if source.Trust == nil {
				source.Trust = &Trust{}
			}
			if source.Trust.Static == nil {
				values := []string{"192.0.2.0/24"}
				source.Trust.Static = &values
			}
			if source.Extract == nil {
				source.Extract = &Extraction{Header: str("X-Real-Ip"), Mode: str("single")}
			}
			if source.Scheme == nil {
				source.Scheme = &Extraction{Header: str("X-Forwarded-Proto"), Mode: str("single")}
			}
		}
		if source.Extract != nil && (source.Extract.Mode == nil || *source.Extract.Mode != "single") {
			return nil, fmt.Errorf("invalid decoded extraction mode")
		}
		if source.Scheme != nil && (source.Scheme.Mode == nil || (*source.Scheme.Mode != "single" && *source.Scheme.Mode != "uniform-list")) {
			return nil, fmt.Errorf("invalid decoded scheme mode")
		}
		if source.Trust != nil && source.Trust.Feeds != nil {
			for _, feed := range *source.Trust.Feeds {
				if feed.RefreshInterval != nil {
					duration, err := time.ParseDuration(*feed.RefreshInterval)
					if err != nil || duration < time.Second {
						return nil, fmt.Errorf("invalid decoded duration")
					}
				}
				if feed.MinEntries != nil {
					text, ok := feed.MinEntries.(string)
					if !ok {
						return nil, fmt.Errorf("fixture expects observed provider decimal string")
					}
					if text == "" {
						return nil, fmt.Errorf("invalid decoded minimum")
					}
					for _, digit := range text {
						if digit < '0' || digit > '9' {
							return nil, fmt.Errorf("invalid decoded minimum")
						}
					}
					minimum, err := strconv.ParseUint(text, 10, 64)
					if err != nil || minimum < 1 || minimum > 100000 {
						return nil, fmt.Errorf("invalid decoded minimum")
					}
				}
			}
		}
	}
	after, _ := json.Marshal(cfg)
	if string(data) != string(after) {
		return nil, fmt.Errorf("borrowed config mutated")
	}
	return &effective, nil
}

type probe struct{ data []byte }

func New(_ context.Context, _ http.Handler, cfg *Config, _ string) (http.Handler, error) {
	effective, err := inspect(cfg)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(map[string]interface{}{"decoded": cfg, "effective": effective, "inputUnchanged": true})
	return &probe{data: data}, err
}
func (p *probe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(p.data)
}
