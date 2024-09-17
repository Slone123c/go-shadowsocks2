package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"

	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// ServerConfig 结构体
type ServerConfig struct {
	Address  string `mapstructure:"address"`
	Cipher   string `mapstructure:"cipher"`
	Password string `mapstructure:"password"`
}

// Config 结构体
type Config struct {
	Servers []ServerConfig `mapstructure:"servers"`
}

// socksLocal 创建一个 SOCKS 服务器，监听 addr 地址，并将流量代理到 server。
func socksLocal(addr, server string, shadow func(net.Conn) net.Conn) {
	logf("SOCKS proxy %s <-> %s", addr, server)
	tcpLocal(addr, server, shadow, func(c net.Conn) (socks.Addr, error) { return socks.Handshake(c) })
}

// tcpTun 创建一个从 addr 到 target 的 TCP 隧道，该隧道通过 server 进行代理。
func tcpTun(addr, server, target string, shadow func(net.Conn) net.Conn) {
	tgt := socks.ParseAddr(target)
	if tgt == nil {
		logf("invalid target address %q", target)
		return
	}
	logf("TCP tunnel %s <-> %s <-> %s", addr, server, target)
	tcpLocal(addr, server, shadow, func(net.Conn) (socks.Addr, error) { return tgt, nil })
}

// tcpLocal 在 addr 监听，并将流量代理到 server，以到达 getAddr 返回的目标地址。
func tcpLocal(addr, server string, shadow func(net.Conn) net.Conn, getAddr func(net.Conn) (socks.Addr, error)) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logf("failed to listen on %s: %v", addr, err)
		return
	}

	for {
		c, err := l.Accept()
		if err != nil {
			logf("failed to accept: %s", err)
			continue
		}

		go func() {
			defer c.Close()
			tgt, err := getAddr(c)
			if err != nil {

				// UDP: 保持连接，直到断开连接，然后释放 UDP socket
				if err == socks.InfoUDPAssociate {
					buf := make([]byte, 1)
					// block here
					for {
						_, err := c.Read(buf)
						if err, ok := err.(net.Error); ok && err.Timeout() {
							continue
						}
						logf("UDP Associate End.")
						return
					}
				}

				logf("failed to get target address: %v", err)
				return
			}

			rc, err := net.Dial("tcp", server)
			if err != nil {
				logf("failed to connect to server %v: %v", server, err)
				return
			}
			defer rc.Close()
			if config.TCPCork {
				rc = timedCork(rc, 10*time.Millisecond, 1280)
			}
			rc = shadow(rc)

			if _, err = rc.Write(tgt); err != nil {
				logf("failed to send target address: %v", err)
				return
			}

			logf("proxy %s <-> %s <-> %s", c.RemoteAddr(), server, tgt)
			if err = relay(rc, c); err != nil {
				logf("relay error: %v", err)
			}
		}()
	}
}

// tcpRemote 监听 addr 地址的传入连接。
func tcpRemote(addr string, shadow func(net.Conn) net.Conn) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logf("failed to listen on %s: %v", addr, err)
		return
	}

	logf("listening TCP on %s", addr)
	for {
		c, err := l.Accept()
		if err != nil {
			logf("failed to accept: %v", err)
			continue
		}

		go func() {
			defer c.Close()
			if config.TCPCork {
				c = timedCork(c, 10*time.Millisecond, 1280)
			}
			sc := shadow(c)

			tgt, err := socks.ReadAddr(sc)
			if err != nil {
				logf("failed to get target address from %v: %v", c.RemoteAddr(), err)
				return
			}

			serverMutex.RLock()
			server := currentServer
			serverMutex.RUnlock()

			for {
				if server == nil {
					logf("no available server")
					return
				}

				ssRemoteAddr := server.Config.Address
				ssCipher := server.Config.Cipher
				ssPassword := server.Config.Password

				ssCipherInst, err := core.PickCipher(ssCipher, nil, ssPassword)
				if err != nil {
					logf("failed to create Shadowsocks cipher for %s: %v", ssRemoteAddr, err)
					break
				}

				ssConn, err := DialWithRawAddr(ssCipherInst, ssRemoteAddr, tgt)
				if err != nil {
					logf("failed to connect to remote Shadowsocks server %s: %v", ssRemoteAddr, err)
					
					// 连接失败，重新检查所有服务器
					for i := range serverList {
						checkServerLatency(&serverList[i])
					}
					serverMutex.Lock()
					server = selectBestServer()
					serverMutex.Unlock()
					continue
				}
				defer ssConn.Close()

				logf("proxy %s <-> %s via Shadowsocks server %s", c.RemoteAddr(), tgt, ssRemoteAddr)

				if err = relay(sc, ssConn); err != nil {
					logf("relay error: %v", err)
				}
				return
			}

			logf("failed to connect to any configured Shadowsocks server")
		}()
	}
}

// DialWithRawAddr 连接到 Shadowsocks 服务器并发送目标地址
func DialWithRawAddr(ssCipherInst core.StreamConnCipher, remoteAddr string, rawaddr []byte) (net.Conn, error) {
	// 先连接到 Shadowsocks 服务器
	conn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to remote Shadowsocks server: %v", err)
	}

	// 包装连接，应用 Shadowsocks 加密
	ssConn := ssCipherInst.StreamConn(conn)

	// 将目标地址 (rawaddr) 发送到 Shadowsocks 服务器
	_, err = ssConn.Write(rawaddr)
	if err != nil {
		ssConn.Close()
		return nil, fmt.Errorf("failed to send target address: %v", err)
	}

	return ssConn, nil
}

// relay 在 left 和 right 之间双向复制数据
func relay(left, right net.Conn) error {
	var err, err1 error
	var wg sync.WaitGroup
	var wait = 5 * time.Second
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err1 = io.Copy(right, left)
		right.SetReadDeadline(time.Now().Add(wait)) // unblock read on right
	}()
	_, err = io.Copy(left, right)
	left.SetReadDeadline(time.Now().Add(wait)) // unblock read on left
	wg.Wait()
	if err1 != nil && !errors.Is(err1, os.ErrDeadlineExceeded) { // requires Go 1.15+
		return err1
	}
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	return nil
}

type corkedConn struct {
	net.Conn
	bufw   *bufio.Writer
	corked bool
	delay  time.Duration
	err    error
	lock   sync.Mutex
	once   sync.Once
}

// timedCork 返回一个包装了原始 Conn 的 corkedConn，它会缓冲写操作，并在指定的延迟后提交。
func timedCork(c net.Conn, d time.Duration, bufSize int) net.Conn {
	return &corkedConn{
		Conn:   c,
		bufw:   bufio.NewWriterSize(c, bufSize),
		corked: true,
		delay:  d,
	}
}

// Write 将数据写入 corkedConn。如果设置了 corked 标志，则会延迟 flush 操作。
func (w *corkedConn) Write(p []byte) (int, error) {
	w.lock.Lock()
	defer w.lock.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	if w.corked {
		w.once.Do(func() {
			time.AfterFunc(w.delay, func() {
				w.lock.Lock()
				defer w.lock.Unlock()
				w.corked = false
				w.err = w.bufw.Flush()
			})
		})
		return w.bufw.Write(p)
	}
	return w.Conn.Write(p)
}
