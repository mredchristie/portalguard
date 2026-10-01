// PortalGuard's app: a window over the engine. It starts `portalguard arm
// -json` through the macOS password prompt, draws the progress feed, and
// sends the user's clicks back on the engine's stdin. It never touches the
// firewall itself. See app.go, and docs/feed.md for the feed.
package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
)

//go:embed all:frontend
var assets embed.FS

func main() {
	app := NewApp()
	err := wails.Run(&options.App{
		Title:            "PortalGuard",
		Width:            420,
		Height:           700,
		DisableResize:    true,
		BackgroundColour: &options.RGBA{R: 5, G: 8, B: 22, A: 255},
		AssetServer:      &assetserver.Options{Assets: assets},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind:             []any{app},
		Mac: &mac.Options{
			TitleBar:             mac.TitleBarHiddenInset(),
			WebviewIsTransparent: false,
			About: &mac.AboutInfo{
				Title:   "PortalGuard",
				Message: "Log in to public Wi-Fi without leaking everything else.",
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}
