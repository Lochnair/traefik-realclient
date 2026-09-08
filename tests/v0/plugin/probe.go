// Package realclientv0 is a V0 observation probe, not a resolver.
package realclientv0

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// No defaults or omitempty: nil pointers, nil slices and empty containers must
// remain distinguishable in the observation. Every struct has a remain map.
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

type probe struct{ config []byte }

// New only serializes the decoded input. It never writes to any reachable data.
func New(_ context.Context, _ http.Handler, cfg *Config, name string) (http.Handler, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	fmt.Printf("V0_NEW %s %s\n", name, string(data))
	fmt.Printf("V0_SHAPES %s sourcesNil=%t\n", name, cfg.Sources == nil)
	for i, source := range cfg.Sources {
		fmt.Printf("V0_SHAPES %s source=%d trustNil=%t schemeNil=%t\n", name, i, source.Trust == nil, source.Scheme == nil)
		if source.Trust != nil {
			fmt.Printf("V0_SHAPES %s source=%d staticPointerNil=%t feedsPointerNil=%t\n", name, i, source.Trust.Static == nil, source.Trust.Feeds == nil)
			if source.Trust.Static != nil {
				fmt.Printf("V0_SHAPES %s source=%d staticSliceNil=%t\n", name, i, *source.Trust.Static == nil)
			}
			if source.Trust.Feeds != nil {
				fmt.Printf("V0_SHAPES %s source=%d feedsSliceNil=%t\n", name, i, *source.Trust.Feeds == nil)
			}
		}
	}
	return &probe{config: data}, nil
}
func (p *probe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(p.config)
}
