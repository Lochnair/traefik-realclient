package realclient

func text(value string) *string { return &value }

// Fresh pure data: overlays only change local containers, never borrowed input.
func preset(name string) (SourceConfig, bool) {
	var c SourceConfig
	var feeds []FeedConfig
	switch name {
	case "bunny":
		feeds = []FeedConfig{{URL: text("https://api.bunny.net/system/edgeserverlist/plain"), Format: text("lines"), RefreshInterval: text("30m"), MinEntries: 1}, {URL: text("https://api.bunny.net/system/edgeserverlist/ipv6"), Format: text("json-array"), RefreshInterval: text("30m"), MinEntries: 1}}
		c.Extract = &HeaderConfig{Header: text("X-Real-Ip"), Mode: text("single")}
	case "cloudflare":
		feeds = []FeedConfig{{URL: text("https://www.cloudflare.com/ips-v4"), Format: text("lines"), RefreshInterval: text("12h"), MinEntries: 1}, {URL: text("https://www.cloudflare.com/ips-v6"), Format: text("lines"), RefreshInterval: text("12h"), MinEntries: 1}}
		c.Extract = &HeaderConfig{Header: text("Cf-Connecting-Ip"), Mode: text("single")}
		c.Scheme = &HeaderConfig{Header: text("X-Forwarded-Proto"), Mode: text("single")}
	default:
		return c, false
	}
	c.Trust = &TrustConfig{Feeds: &feeds}
	return c, true
}
func expandPreset(c SourceConfig) (SourceConfig, error) {
	if c.Preset == nil {
		return c, nil
	}
	result, ok := preset(*c.Preset)
	if !ok {
		return result, errPreset(*c.Preset)
	}
	if c.Trust != nil {
		t := c.Trust
		if t.Static != nil {
			result.Trust.Static = t.Static
		}
		if t.Feeds != nil {
			result.Trust.Feeds = t.Feeds
		}
		if t.HeaderIn != nil {
			result.Trust.HeaderIn = t.HeaderIn
		}
		if t.HostExact != nil {
			result.Trust.HostExact = t.HostExact
		}
		if t.HostSuffixes != nil {
			result.Trust.HostSuffixes = t.HostSuffixes
		}
	}
	if c.Extract != nil {
		result.Extract = c.Extract
	}
	if c.Scheme != nil {
		result.Scheme = c.Scheme
	}
	return result, nil
}
