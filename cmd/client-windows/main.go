// mschapv3-client-windows — локальный прокси (SOCKS5 + HTTP на одном порту)
// поверх туннеля MS-CHAPv3, который включает системный прокси Windows
// и возвращает прежние настройки при выходе.
//
//	mschapv3-client-windows.exe -c client.json
//	mschapv3-client-windows.exe -no-sysproxy      (не трогать настройки системы)
//	mschapv3-client-windows.exe -unset            (аварийно выключить системный прокси)
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"mschapv3proxy/internal/localproxy"
	"mschapv3proxy/internal/tunnel"
)

func main() {
	cfgPath := flag.String("c", "client.json", "path to client config")
	noSys := flag.Bool("no-sysproxy", false, "do not change Windows system proxy settings")
	unset := flag.Bool("unset", false, "disable the system proxy and exit")
	flag.Parse()

	if *unset {
		if err := clearSystemProxy(); err != nil {
			log.Fatal(err)
		}
		log.Println("system proxy disabled")
		return
	}

	cfg, err := tunnel.LoadConfig(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:1081"
	}
	cl, err := tunnel.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("proxy (SOCKS5+HTTP) on %s -> %s (tls=%v)", cfg.Listen, cfg.Server, cfg.TLS.Enabled)

	var saved *savedProxy
	if !*noSys {
		saved, err = setSystemProxy(cfg.Listen)
		if err != nil {
			log.Fatalf("set system proxy: %v", err)
		}
		log.Println("Windows system proxy enabled; it will be restored on exit (Ctrl+C)")
	}

	go localproxy.ServeWithUDP(ln, cl.Dial, cl.DialUDP)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	ln.Close()
	if saved != nil {
		saved.restore()
		log.Println("system proxy restored")
	}
}
