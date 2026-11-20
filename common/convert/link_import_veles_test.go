package convert_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	. "github.com/metacubex/mihomo/common/convert"
	"github.com/metacubex/mihomo/common/structure"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// P33: REALITY downloadSettings keep serverName, fingerprint and password (Xray name for publicKey).
func TestVelesVlessDownloadSettingsRealityFields(t *testing.T) {
	extra := `{"downloadSettings":{"address":"dl.example.com","port":443,"security":"reality","realitySettings":{"serverName":"dl-sni.example.com","fingerprint":"firefox","password":"PASSWORDKEY","shortId":"abcd"},"xhttpSettings":{"path":"/dl"}}}`
	link := "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&type=xhttp&path=%2Fup&extra=" + url.QueryEscape(extra) + "#n"

	proxies, err := ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	require.Len(t, proxies, 1)
	ds := proxies[0]["xhttp-opts"].(map[string]any)["download-settings"].(map[string]any)
	assert.Equal(t, "dl.example.com", ds["server"])
	assert.Equal(t, true, ds["tls"])
	assert.Equal(t, "dl-sni.example.com", ds["servername"])
	assert.Equal(t, "firefox", ds["client-fingerprint"])
	assert.Equal(t, map[string]any{"public-key": "PASSWORDKEY", "short-id": "abcd"}, ds["reality-opts"])

	// when both are set, Xray uses password
	extra = `{"downloadSettings":{"address":"dl.example.com","security":"reality","realitySettings":{"publicKey":"PUBLICKEY","password":"PASSWORDKEY"}}}`
	link = "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&type=xhttp&extra=" + url.QueryEscape(extra) + "#n"
	proxies, err = ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	ds = proxies[0]["xhttp-opts"].(map[string]any)["download-settings"].(map[string]any)
	assert.Equal(t, map[string]any{"public-key": "PASSWORDKEY"}, ds["reality-opts"])
}

// P33: vcn (Xray verifyPeerCertByName) and pcs (pinnedPeerCertSha256) lists are imported.
func TestVelesImportsVcnAndPcsLists(t *testing.T) {
	hash1 := strings.Repeat("ab", 32)
	hash2 := strings.Repeat("cd", 32)

	for _, vcn := range []string{"a.example", "a.example,b.example"} {
		link := "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&type=tcp&vcn=" + url.QueryEscape(vcn) + "#n"
		proxies, err := ConvertsV2Ray([]byte(link))
		require.NoError(t, err)
		require.Len(t, proxies, 1)
		assert.Equal(t, vcn, proxies[0]["name-cert-verify"])
	}

	pcs := hash1 + "," + hash2
	link := "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&type=tcp&pcs=" + pcs + "&vcn=a.example#n"
	proxies, err := ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	require.Len(t, proxies, 1)
	assert.Equal(t, pcs, proxies[0]["fingerprint"])
	_, err = adapter.ParseProxy(proxies[0])
	require.NoError(t, err)

	link = "trojan://secret@example.com:443?type=tcp&pcs=" + pcs + "&vcn=a.example,b.example#n"
	proxies, err = ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	require.Len(t, proxies, 1)
	assert.Equal(t, pcs, proxies[0]["fingerprint"])
	assert.Equal(t, "a.example,b.example", proxies[0]["name-cert-verify"])
	_, err = adapter.ParseProxy(proxies[0])
	require.NoError(t, err)
}

// P33: in Xray downloadSettings has its own streamSettings. pcs/vcn of the main link must not
// leak into a download channel with its own tlsSettings, and its own pcs/vcn are imported.
func TestVelesVlessDownloadSettingsOwnCertVerify(t *testing.T) {
	hash1 := strings.Repeat("ab", 32)
	hash2 := strings.Repeat("cd", 32)
	parse := func(extra string) (map[string]any, *outbound.XHTTPDownloadSettings) {
		t.Helper()
		link := "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&type=xhttp&sni=front.example&vcn=front.example&pcs=" + hash1 + "&extra=" + url.QueryEscape(extra) + "#n"
		proxies, err := ConvertsV2Ray([]byte(link))
		require.NoError(t, err)
		require.Len(t, proxies, 1)
		assert.Equal(t, "front.example", proxies[0]["name-cert-verify"])
		_, err = adapter.ParseProxy(proxies[0])
		require.NoError(t, err)
		option := &outbound.VlessOption{}
		decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
		require.NoError(t, decoder.Decode(proxies[0], option))
		ds := option.XHTTPOpts.DownloadSettings
		require.NotNil(t, ds)
		return proxies[0]["xhttp-opts"].(map[string]any)["download-settings"].(map[string]any), ds
	}

	// own tlsSettings without vcn/pcs: verified by its own SNI, nothing inherited
	m, ds := parse(`{"downloadSettings":{"address":"dl.example","security":"tls","tlsSettings":{"serverName":"dl.example"}}}`)
	assert.Equal(t, "", m["name-cert-verify"])
	assert.Equal(t, "", m["fingerprint"])
	require.NotNil(t, ds.NameCertVerify, "empty value must reach the outbound as a set pointer")
	require.NotNil(t, ds.Fingerprint)
	assert.Equal(t, "", lo.FromPtrOr(ds.NameCertVerify, "front.example"))
	assert.Equal(t, "", lo.FromPtrOr(ds.Fingerprint, hash1))

	// own reality serverName: nothing inherited either
	m, _ = parse(`{"downloadSettings":{"address":"dl.example","security":"reality","realitySettings":{"serverName":"dl.example","publicKey":"ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw"}}}`)
	assert.Equal(t, "", m["name-cert-verify"])
	assert.Equal(t, "", m["fingerprint"])

	// own vcn/pcs: as a string and as an array, trimmed, empty elements dropped
	m, ds = parse(`{"downloadSettings":{"address":"dl.example","security":"tls","tlsSettings":{"serverName":"dl.example","verifyPeerCertByName":" a.example, ,b.example","pinnedPeerCertSha256":"` + hash2 + `"}}}`)
	assert.Equal(t, "a.example,b.example", m["name-cert-verify"])
	assert.Equal(t, hash2, m["fingerprint"])
	assert.Equal(t, "a.example,b.example", lo.FromPtrOr(ds.NameCertVerify, "front.example"))
	m, _ = parse(`{"downloadSettings":{"address":"dl.example","security":"tls","tlsSettings":{"verifyPeerCertByName":["a.example","b.example"],"pinnedPeerCertSha256":["` + hash1 + `","` + hash2 + `"]}}}`)
	assert.Equal(t, "a.example,b.example", m["name-cert-verify"])
	assert.Equal(t, hash1+","+hash2, m["fingerprint"])

	// negative: no own tlsSettings and no own SNI - the download channel keeps inheriting the main TLS
	m, ds = parse(`{"downloadSettings":{"address":"dl.example","security":"tls"}}`)
	assert.NotContains(t, m, "name-cert-verify")
	assert.NotContains(t, m, "fingerprint")
	assert.Nil(t, ds.NameCertVerify)
	assert.Nil(t, ds.Fingerprint)
}

// P33: like Xray, a pcs/vcn list that is empty after trimming is not imported (verification by SNI).
func TestVelesEmptyVcnPcsListsNotImported(t *testing.T) {
	for _, value := range []string{",", " , ", " "} {
		q := url.QueryEscape(value)
		link := "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&type=tcp&vcn=" + q + "&pcs=" + q + "#n"
		proxies, err := ConvertsV2Ray([]byte(link))
		require.NoError(t, err)
		require.Len(t, proxies, 1)
		assert.NotContains(t, proxies[0], "name-cert-verify", "vless vcn=%q", value)
		assert.NotContains(t, proxies[0], "fingerprint", "vless pcs=%q", value)

		link = "trojan://secret@example.com:443?type=tcp&vcn=" + q + "&pcs=" + q + "#n"
		proxies, err = ConvertsV2Ray([]byte(link))
		require.NoError(t, err)
		require.Len(t, proxies, 1)
		assert.NotContains(t, proxies[0], "name-cert-verify", "trojan vcn=%q", value)
		assert.NotContains(t, proxies[0], "fingerprint", "trojan pcs=%q", value)
	}

	// elements are trimmed, empty ones dropped
	link := "trojan://secret@example.com:443?type=tcp&vcn=" + url.QueryEscape(" a.example, ,b.example ") + "#n"
	proxies, err := ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	assert.Equal(t, "a.example,b.example", proxies[0]["name-cert-verify"])
}
