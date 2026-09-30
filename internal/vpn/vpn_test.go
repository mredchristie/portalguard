package vpn

import "testing"

const list = `Available network connection services in the current set (*=enabled):
* (Disconnected)   887B3792-3B6E-415F-9E4B-E57C0678DD61 VPN (com.wireguard.macos) "My VPN"                    [VPN:com.wireguard.macos]
  (Connected)      11111111-2222-3333-4444-555555555555 IPSec              "Work"                           [IPSec]
`

func TestParseList(t *testing.T) {
	ss := parseList(list)
	if len(ss) != 2 {
		t.Fatalf("parsed %d services: %+v", len(ss), ss)
	}
	wg := ss[0]
	if wg.Name != "My VPN" || wg.ID != "887B3792-3B6E-415F-9E4B-E57C0678DD61" || !wg.Enabled || wg.Status != "Disconnected" || !wg.WireGuard() {
		t.Errorf("wireguard service = %+v", wg)
	}
	if ss[1].Name != "Work" || ss[1].Kind != "IPSec" || ss[1].Enabled || ss[1].WireGuard() {
		t.Errorf("ipsec service = %+v", ss[1])
	}
	if s, ok := Find(ss, "My VPN"); !ok || s.ID != wg.ID {
		t.Error("not found by name")
	}
	if _, ok := Find(ss, "887b3792-3b6e-415f-9e4b-e57c0678dd61"); !ok {
		t.Error("not found by lower-case ID")
	}
}

func TestParseRemoteReadsOnlyTheAddress(t *testing.T) {
	show := `VPN <dictionary> {
  PasswordReference : <data> 0x7373756900
  RemoteAddress : 203.0.113.10:51820
}`
	if h, p := parseRemote(show); h != "203.0.113.10" || p != 51820 {
		t.Errorf("parseRemote = %q, %d", h, p)
	}
	if h, p := parseRemote("  RemoteAddress : vpn.example.com\n"); h != "vpn.example.com" || p != 0 {
		t.Errorf("host only: %q, %d", h, p)
	}
	if h, _ := parseRemote("nothing here"); h != "" {
		t.Errorf("found %q in nothing", h)
	}
}
