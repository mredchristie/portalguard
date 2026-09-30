//go:build !darwin

package vpn

import "context"

func List(context.Context) ([]Service, error)             { return nil, ErrUnsupported }
func Remote(context.Context, string) (string, int, error) { return "", 0, ErrUnsupported }
func Start(context.Context, string) error                 { return ErrUnsupported }
