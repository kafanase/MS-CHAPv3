// mschapv3-client-termux — локальный SOCKS5-прокси (заодно понимает HTTP CONNECT)
// поверх туннеля MS-CHAPv3. Предназначен для Termux / Linux / Android (linux/arm64).
//
//	./mschapv3-client-termux -c client.json
//	export ALL_PROXY=socks5h://127.0.0.1:1080
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
	flag.Parse()

	cfg, err := tunnel.LoadConfig(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:1080"
	}
	// В Termux нет /etc/resolv.conf — Go-резолвер не работает без явного DNS.
	if cfg.DNS == "" {
		cfg.DNS = "1.1.1.1:53"
	}
	cl, err := tunnel.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("SOCKS5 on %s -> %s (tls=%v)", cfg.Listen, cfg.Server, cfg.TLS.Enabled)

	go localproxy.Serve(ln, cl.Dial)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	ln.Close()
}
