//go:build !windows

package main

import "errors"

type savedProxy struct{}

func (s *savedProxy) restore() {}

func setSystemProxy(string) (*savedProxy, error) {
	return nil, errors.New("system proxy is supported on Windows only; use -no-sysproxy")
}

func clearSystemProxy() error { return errors.New("Windows only") }
