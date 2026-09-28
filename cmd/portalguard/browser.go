package main

import (
	"fmt"
	"os/exec"
	"runtime"
)

// openBrowser asks the OS to open url in the default browser.
//
// Best-effort: the caller has already printed the URL, so a failure here
// costs nothing but the convenience. url comes from the portal's own
// redirect - untrusted network input - but it is passed as a single argv
// entry to the OS opener, never through a shell, so there is nothing for it
// to inject.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("no known way to open a browser on %s", runtime.GOOS)
	}
	return cmd.Start()
}
