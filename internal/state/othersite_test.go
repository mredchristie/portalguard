package state

import "testing"

// TestOtherSiteKind against what EE WiFi's run actually refused: of 55
// names, almost none are worth offering, and a payment host would stand out.
func TestOtherSiteKind(t *testing.T) {
	cases := map[string]string{
		"secure.worldpay.com":                     "payment",
		"hpp.sandbox.realexpayments.com":          "payment",
		"acs.cardinalcommerce.com":                "payment",
		"checkout.stripe.com":                     "payment",
		"login.hotelportal-partner.net":           "other",
		"mtalk.google.com":                        "",
		"1-courier.push.apple.com":                "",
		"gew4-spclient.spotify.com":               "",
		"imap.gmail.com":                          "",
		"alive.github.com":                        "",
		"api.whatsapp.net":                        "",
		"api.anthropic.com":                       "",
		"ocsp.digicert.com":                       "",
		"cloudflare-dns.com":                      "",
		"example.org":                             "",
		"lb._dns-sd._udp.btwifi.com":              "",
		"_aaplcache._tcp.btwifi.com":              "",
		"0.1.95.100.in-addr.arpa":                 "",
		"pg-e59a67339f1b2c83.portalguard.invalid": "",
		"localhost":                               "",
	}
	for name, want := range cases {
		if got := OtherSiteKind(name); got != want {
			t.Errorf("OtherSiteKind(%q) = %q, want %q", name, got, want)
		}
	}
}
