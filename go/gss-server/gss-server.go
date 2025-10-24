// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	_ "github.com/golang-auth/go-gssapi-c"
	"github.com/golang-auth/go-gssapi/v3"
)

var _debug bool

var provider string = "github.com/golang-auth/go-gssapi-c"
var gss = gssapi.MustNewProvider(provider)

func main() {
	port := flag.Int("port", 1234, "local port to listen on")
	flag.BoolVar(&_debug, "debug", false, "enable debugging")
	flag.Parse()

	// Listen on port
	addr := fmt.Sprintf(":%d", *port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}

		go handleConn(conn)
	}
}

func sendToken(conn net.Conn, token []byte) error {
	szBuff := make([]byte, 4)
	binary.BigEndian.PutUint32(szBuff, uint32(len(token)))
	_, err := conn.Write(szBuff)
	if err != nil {
		return err
	}

	_, err = conn.Write(token)
	if err != nil {
		return err
	}

	return nil
}

func formatToken(tok []byte) string {
	b := &strings.Builder{}

	bd := hex.Dumper(b)
	defer bd.Close()

	bd.Write(tok)
	return b.String()
}

func recvToken(conn net.Conn) (token []byte, err error) {
	szBuff := make([]byte, 4)
	_, err = io.ReadFull(conn, szBuff)
	if err != nil {
		return
	}

	buf := bytes.NewBuffer(szBuff)
	var tokenSize uint32
	binary.Read(buf, binary.BigEndian, &tokenSize)

	token = make([]byte, tokenSize)
	_, err = io.ReadFull(conn, token)
	if err != nil {
		return
	}

	return
}

func debug(format string, args ...interface{}) {
	if !_debug {
		return
	}

	fmt.Printf(format+"\n", args...)
}

func handleConn(conn net.Conn) error {
	defer conn.Close()

	debug("Accepted connection from %s", conn.RemoteAddr())

	secctx, err := gss.AcceptSecContext()
	if err != nil {
		return showErr(err)
	}

	defer secctx.Delete()

	for secctx.ContinueNeeded() {
		inToken, err := recvToken(conn)
		if err != nil {
			return showErr(err)
		}
		debug("Read context token (%d bytes:", len(inToken))
		debug("%s", formatToken(inToken))

		outToken, info, err := secctx.Continue(inToken)
		if len(outToken) > 0 {
			if err := sendToken(conn, outToken); err != nil {
				return showErr(err)
			}
			debug("Sent context token (%d bytes):", len(outToken))
			debug("%s", formatToken(outToken))
		}
		if err != nil {
			log.Fatal(err)
		}

		debug("Context information: %+v", info)
	}

	info, err := secctx.Inquire()
	if err != nil {
		return showErr(err)
	}
	printContextInfo(info)

	inMsg, err := recvToken(conn)
	if err != nil {
		return showErr(err)
	}
	debug("Received wrap message (%d bytes):\n%s", len(inMsg), formatToken(inMsg))

	origMsg, conf, _, err := secctx.Unwrap(inMsg)
	if err != nil {
		return showErr(err)
	}

	protStr := "signed"
	if conf {
		protStr = "sealed"
	}
	fmt.Printf(`Received %s message: "%s"`+"\n", protStr, origMsg)

	// generate a MIC token to send back
	outToken, err := secctx.GetMIC(origMsg, 0)
	if err != nil {
		return showErr(err)
	}

	if err = sendToken(conn, outToken); err != nil {
		return showErr(err)
	}
	debug("Sent MIC message (%d bytes):\n%s", len(outToken), formatToken(outToken))

	return nil
}

func showErr(err error) error {
	log.Printf("ERROR: %s", err)
	return err
}

func printContextInfo(info *gssapi.SecContextInfo) {
	local := "remotely initiated"
	open := "closed"

	if info.LocallyInitiated {
		local = "locally initiated"
	}
	if info.FullyEstablished {
		open = "open"
	}

	var expiresAt string
	switch {
	default:
		expiresAt = info.ExpiresAt.ExpiresAt.Format(time.RFC3339)
	case info.ExpiresAt.Status == gssapi.GssLifetimeIndefinite:
		expiresAt = "indefinite"
	case info.ExpiresAt.Status == gssapi.GssLifetimeExpired:
		expiresAt = "expired"
	}

	initName, initNameType, err := info.InitiatorName.Display()
	if err != nil {
		log.Fatal(err)
	}
	acceptName, acceptNameType, err := info.AcceptorName.Display()
	if err != nil {
		log.Fatal(err)
	}

	debug("Context flags: %s", info.Flags)
	debug("\"%s\" to \"%s\", expires: %s, %s, %s",
		initName, acceptName,
		expiresAt,
		local,
		open)

	debug("Name type of source is %s (%s)", initNameType, initNameType.OidString())
	debug("Name type of destination is %s (%s)", acceptNameType, acceptNameType.OidString())
	debug("Mechanism: %s (%s)", info.Mech, info.Mech.OidString())
}
