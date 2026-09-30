package state

import (
	"strings"

	"portalguard/internal/firewall"
)

// ==== which refused names are worth offering ===============================
//
// A login that goes somewhere else to take payment (a card processor, a 3-D
// Secure check) stalls on a name the filter refused, on a site auto-allow
// will not open by itself. The terminal's -verbose lists every refusal; an
// app cannot, because nearly all of them are the Mac's background apps (55
// of them at EE WiFi). OtherSiteKind picks out the few worth showing.

// paymentMarks are names card payment runs through.
var paymentMarks = []string{
	"worldpay", "stripe", "paypal", "adyen", "braintree", "sagepay", "opayo",
	"checkout.com", "cybersource", "globalpay", "realexpayments", "payment",
	"3dsecure", "3ds.", "cardinalcommerce", "securecode", "verifiedbyvisa",
	"mastercard", "visa.com", "klarna", "squareup", "judopay", "paysafe",
	"apple-pay-gateway",
}

// backgroundMarks are background services the report's categories do not
// name, seen asking during real logins: never what a login page needs.
var backgroundMarks = []string{
	"github", "whatsapp", "facebook", "instagram", "microsoft", "windows.com",
	"office", "skype", "digicert", "ocsp", "crl.", "letsencrypt", "mozilla",
	"firefox", "cloudflare-dns", "dns.google", "example.org", "example.com",
	"anthropic", "openai", "slack", "discord", "zoom.us", "adobe", "amazonaws",
	"doubleclick", "googletag", "twitter", "x.com", "tiktok", "snapchat",
}

// OtherSiteKind says what a refused name looks like, for offering it to open:
// "payment" for a card processor, "other" for an unrecognised site, and ""
// for what is certainly background noise, not worth showing.
func OtherSiteKind(name string) string {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	switch {
	case n == "" || !strings.Contains(n, "."):
		return ""
	case strings.HasSuffix(n, ".arpa"), strings.HasSuffix(n, ".local"), strings.HasSuffix(n, ".invalid"):
		return ""
	case strings.HasPrefix(n, "_") || strings.Contains(n, "._"):
		return "" // service discovery: _dns-sd._udp, _aaplcache._tcp
	}
	for _, m := range paymentMarks {
		if strings.Contains(n, m) {
			return "payment"
		}
	}
	if firewall.HostnameCategory(n) != "other" {
		return ""
	}
	for _, m := range backgroundMarks {
		if strings.Contains(n, m) {
			return ""
		}
	}
	return "other"
}
