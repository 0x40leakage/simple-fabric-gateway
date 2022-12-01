package xinan

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	flogging "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkpatch/logbridge"
)

var (
	logger              = flogging.MustGetLogger("gm_xin_an")
	ctxMap              = make(map[string]*ctx)
	defaultSockPoolSize = 4
)

type HSMServer struct {
	xinanctx *ctx
	sockPool chan int32
	IP       string
	Port     int32
	Passwd   string
}

func NewHSMServer(ip, port, passwd, ldPath string) (*HSMServer, error) {
	_, err := os.Stat(ldPath)
	if os.IsNotExist(err) {
		return nil, err
	}
	c := ctxMap[ldPath]
	if c == nil {
		c = newCtx(ldPath)
		ctxMap[ldPath] = c
	}

	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("convert port failed, %s", err)
	}
	pool := make(chan int32, defaultSockPoolSize)
	return &HSMServer{xinanctx: c, IP: ip, Port: int32(p), Passwd: passwd, sockPool: pool}, nil
}

func (s *HSMServer) getSockFd() (sockFd int32, err error) {
	for {
		select {
		case sockFd = <-s.sockPool:
			return
		default:
			// cache is empty (or completely in use), create a new session
			return s.createSockFd()
		}
	}
}

func (s *HSMServer) createSockFd() (sockFd int32, err error) {
	// attempt 10 times to open a session with a 100ms delay after each attempt
	for i := 0; i < 10; i++ {
		sockFd, err = s.Connection()
		if err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	return
}

func (s *HSMServer) closeSockFd(sockFd int32) {
	if err := s.DisConnection(sockFd); err != nil {
		logger.Debug("CloseSession failed", err)
	}
}

func (s *HSMServer) returnSockFd(sockFd int32) {
	select {
	case s.sockPool <- sockFd:
		// returned session back to session cache
	default:
		// have plenty of sessions in cache, dropping
		s.closeSockFd(sockFd)
	}
}

func (s *HSMServer) handleSockFdReturn(err error, sockFd int32) {
	if err != nil {
		if strings.Contains(err.Error(), "-80") {
			logger.Infof("xinan sock invalid", err)
			s.closeSockFd(sockFd)
			return
		}
	}
	s.returnSockFd(sockFd)
}

func (server *HSMServer) Connection() (int32, error) {
	sfd, err := server.xinanctx.connToNetSign(server.IP, server.Port, server.Passwd)
	if err != nil {
		logger.Errorf("connToNetSign Error %s", err)
		return -1, err
	}
	return sfd, nil
}

func (server *HSMServer) DisConnection(sockFd int32) error {
	if server != nil && sockFd != -1 {
		if err := server.xinanctx.discFromNetSign(sockFd); err != nil {
			return err
		}
	}
	return nil
}

func (server *HSMServer) GetServerVersion() string {
	return server.xinanctx.getServerVersion()
}
