//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

const regKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

type regVal struct {
	typ, val string
	ok       bool
}

type savedProxy struct{ enable, server, override regVal }

func reg(args ...string) (string, error) {
	cmd := exec.Command("reg", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func regQuery(name string) regVal {
	out, err := reg("query", regKey, "/v", name)
	if err != nil {
		return regVal{}
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && strings.EqualFold(f[0], name) {
			return regVal{typ: f[1], val: strings.Join(f[2:], " "), ok: true}
		}
	}
	return regVal{}
}

func regSet(name, typ, val string) error {
	if out, err := reg("add", regKey, "/v", name, "/t", typ, "/d", val, "/f"); err != nil {
		return fmt.Errorf("reg add %s: %v: %s", name, err, strings.TrimSpace(out))
	}
	return nil
}

func regRestore(name string, v regVal) {
	if v.ok {
		regSet(name, v.typ, v.val)
	} else {
		reg("delete", regKey, "/v", name, "/f")
	}
}

// Уведомляет WinINet/приложения об изменении настроек прокси.
func notifyChange() {
	proc := syscall.NewLazyDLL("wininet.dll").NewProc("InternetSetOptionW")
	proc.Call(0, 39, 0, 0) // INTERNET_OPTION_SETTINGS_CHANGED
	proc.Call(0, 37, 0, 0) // INTERNET_OPTION_REFRESH
}

func setSystemProxy(addr string) (*savedProxy, error) {
	s := &savedProxy{regQuery("ProxyEnable"), regQuery("ProxyServer"), regQuery("ProxyOverride")}
	if err := regSet("ProxyServer", "REG_SZ", addr); err != nil {
		return nil, err
	}
	regSet("ProxyOverride", "REG_SZ", "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2*;172.30.*;172.31.*;192.168.*;<local>")
	if err := regSet("ProxyEnable", "REG_DWORD", "1"); err != nil {
		return nil, err
	}
	notifyChange()
	return s, nil
}

func (s *savedProxy) restore() {
	regRestore("ProxyEnable", s.enable)
	regRestore("ProxyServer", s.server)
	regRestore("ProxyOverride", s.override)
	notifyChange()
}

func clearSystemProxy() error {
	if err := regSet("ProxyEnable", "REG_DWORD", "0"); err != nil {
		return err
	}
	notifyChange()
	return nil
}
