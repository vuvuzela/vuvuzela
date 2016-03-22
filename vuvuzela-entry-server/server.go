package main

import (
	"flag"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/websocket"

	. "github.com/davidlazar/vuvuzela"
	. "github.com/davidlazar/vuvuzela/internal"
	"github.com/davidlazar/vuvuzela/vrpc"
)

type server struct {
	connectionsMu sync.Mutex
	connections   map[*connection]bool

	convoMu       sync.Mutex
	convoRound    uint32
	convoRequests []*convoReq

	dialMu       sync.Mutex
	dialRound    uint32
	dialRequests []*dialReq

	firstServer *vrpc.Client
	lastServer  *vrpc.Client
}

type convoReq struct {
	conn  *connection
	onion []byte
}

type dialReq struct {
	conn  *connection
	onion []byte
}

type connection struct {
	sync.Mutex

	ws        *websocket.Conn
	srv       *server
	publicKey *BoxKey
}

func (srv *server) register(c *connection) {
	srv.connectionsMu.Lock()
	srv.connections[c] = true
	srv.connectionsMu.Unlock()
}

func (srv *server) allConnections() []*connection {
	srv.connectionsMu.Lock()
	conns := make([]*connection, len(srv.connections))
	i := 0
	for c := range srv.connections {
		conns[i] = c
		i++
	}
	srv.connectionsMu.Unlock()
	return conns
}

func broadcast(conns []*connection, v interface{}) {
	ParallelFor(len(conns), func(p *P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			conns[i].Send(v)
		}
	})
}

func (c *connection) Close() {
	c.ws.Close()

	c.srv.connectionsMu.Lock()
	delete(c.srv.connections, c)
	c.srv.connectionsMu.Unlock()
}

func (c *connection) Send(v interface{}) {
	const writeWait = 10 * time.Second

	e, err := Envelop(v)
	if err != nil {
		log.WithFields(log.Fields{"bug": true, "call": "Envelop"}).Error(err)
		return
	}

	c.Lock()
	c.ws.SetWriteDeadline(time.Now().Add(writeWait))
	if err := c.ws.WriteJSON(e); err != nil {
		log.WithFields(log.Fields{"call": "WriteJSON"}).Debug(err)
		c.Unlock()
		c.Close()
		return
	}
	c.Unlock()
}

func (c *connection) readLoop() {
	for {
		var e Envelope
		if err := c.ws.ReadJSON(&e); err != nil {
			log.WithFields(log.Fields{"call": "ReadJSON"}).Debug(err)
			c.Close()
			break
		}

		v, err := e.Open()
		if err != nil {
			msg := fmt.Sprintf("error parsing request: %s", err)
			go c.Send(&BadRequestError{Err: msg})
		}
		go c.handleRequest(v)
	}
}

func (c *connection) handleRequest(v interface{}) {
	switch v := v.(type) {
	case *ConvoRequest:
		c.handleConvoRequest(v)
	case *DialRequest:
		c.handleDialRequest(v)
	}
}

func (c *connection) handleConvoRequest(r *ConvoRequest) {
	srv := c.srv
	srv.convoMu.Lock()
	currRound := srv.convoRound
	if r.Round != currRound {
		srv.convoMu.Unlock()
		err := fmt.Sprintf("wrong round (currently %d)", currRound)
		go c.Send(&ConvoError{Round: r.Round, Err: err})
		return
	}
	rr := &convoReq{
		conn:  c,
		onion: r.Onion,
	}
	srv.convoRequests = append(srv.convoRequests, rr)
	srv.convoMu.Unlock()
}

func (c *connection) handleDialRequest(r *DialRequest) {
	srv := c.srv
	srv.dialMu.Lock()
	currRound := srv.dialRound
	if r.Round != currRound {
		srv.dialMu.Unlock()
		err := fmt.Sprintf("wrong round (currently %d)", currRound)
		go c.Send(&DialError{Round: r.Round, Err: err})
		return
	}
	rr := &dialReq{
		conn:  c,
		onion: r.Onion,
	}
	srv.dialRequests = append(srv.dialRequests, rr)
	srv.dialMu.Unlock()
}

func (srv *server) convoRoundLoop() {
	for {
		if err := NewConvoRound(srv.firstServer, srv.convoRound); err != nil {
			log.WithFields(log.Fields{"service": "convo", "round": srv.convoRound, "call": "NewConvoRound"}).Error(err)
			time.Sleep(10 * time.Second)
			continue
		}
		log.WithFields(log.Fields{"service": "convo", "round": srv.convoRound}).Info("Broadcast")

		broadcast(srv.allConnections(), &AnnounceConvoRound{srv.convoRound})
		time.Sleep(*receiveWait)

		srv.convoMu.Lock()
		go srv.runConvoRound(srv.convoRound, srv.convoRequests)

		srv.convoRound += 1
		srv.convoRequests = make([]*convoReq, 0, len(srv.convoRequests))
		srv.convoMu.Unlock()
	}
}

func (srv *server) dialRoundLoop() {
	for {
		time.Sleep(DialWait)
		if err := NewDialRound(srv.firstServer, srv.dialRound); err != nil {
			log.WithFields(log.Fields{"service": "dial", "round": srv.dialRound, "call": "NewDialRound"}).Error(err)
			time.Sleep(10 * time.Second)
			continue
		}
		log.WithFields(log.Fields{"service": "dial", "round": srv.dialRound}).Info("Broadcast")

		broadcast(srv.allConnections(), &AnnounceDialRound{srv.dialRound, TotalDialBuckets})
		time.Sleep(*receiveWait)

		srv.dialMu.Lock()
		go srv.runDialRound(srv.dialRound, srv.dialRequests)

		srv.dialRound += 1
		srv.dialRequests = make([]*dialReq, 0, len(srv.dialRequests))
		srv.dialMu.Unlock()
	}
}

func (srv *server) runConvoRound(round uint32, requests []*convoReq) {
	conns := make([]*connection, len(requests))
	onions := make([][]byte, len(requests))
	for i, r := range requests {
		conns[i] = r.conn
		onions[i] = r.onion
	}

	rlog := log.WithFields(log.Fields{"service": "convo", "round": round})
	rlog.WithFields(log.Fields{"call": "RunConvoRound", "onions": len(onions)}).Info()

	replies, err := RunConvoRound(srv.firstServer, round, onions)
	if err != nil {
		rlog.WithFields(log.Fields{"call": "RunConvoRound"}).Error(err)
		broadcast(conns, &ConvoError{Round: round, Err: "server error"})
		return
	}

	rlog.WithFields(log.Fields{"replies": len(replies)}).Info("Success")

	ParallelFor(len(replies), func(p *P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			reply := &ConvoResponse{
				Round: round,
				Onion: replies[i],
			}
			conns[i].Send(reply)
		}
	})
}

func (srv *server) runDialRound(round uint32, requests []*dialReq) {
	conns := make([]*connection, len(requests))
	onions := make([][]byte, len(requests))
	for i, r := range requests {
		conns[i] = r.conn
		onions[i] = r.onion
	}

	rlog := log.WithFields(log.Fields{"service": "dial", "round": round})
	rlog.WithFields(log.Fields{"call": "RunDialRound", "onions": len(onions)}).Info()

	if err := RunDialRound(srv.firstServer, round, onions); err != nil {
		rlog.WithFields(log.Fields{"call": "RunDialRound"}).Error(err)
		broadcast(conns, &DialError{Round: round, Err: "server error"})
		return
	}

	args := &DialBucketsArgs{Round: round}
	result := new(DialBucketsResult)
	if err := srv.lastServer.Call("DialService.Buckets", args, result); err != nil {
		rlog.WithFields(log.Fields{"call": "Buckets"}).Error(err)
		broadcast(conns, &DialError{Round: round, Err: "server error"})
		return
	}

	intros := 0
	for _, b := range result.Buckets {
		intros += len(b)
	}
	rlog.WithFields(log.Fields{"buckets": len(result.Buckets), "intros": intros}).Info("Buckets")

	ParallelFor(len(conns), func(p *P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			c := conns[i]
			bi := KeyDialBucket(c.publicKey, TotalDialBuckets)

			db := &DialBucket{
				Round:  round,
				Intros: result.Buckets[bi-1],
			}
			c.Send(db)
		}
	})
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func (srv *server) wsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	pk, err := KeyFromString(r.URL.Query().Get("publickey"))
	if err != nil {
		http.Error(w, "expecting box key in publickey query parameter", http.StatusBadRequest)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Upgrade: %s", err)
		return
	}

	c := &connection{
		ws:        ws,
		srv:       srv,
		publicKey: pk,
	}
	srv.register(c)
	c.readLoop()
}

var addr = flag.String("addr", ":8080", "http service address")
var pkiPath = flag.String("pki", "confs/pki.conf", "pki file")
var receiveWait = flag.Duration("wait", DefaultReceiveWait, "")

func main() {
	flag.Parse()
	log.SetFormatter(&ServerFormatter{})

	pki := ReadPKI(*pkiPath)

	firstServer, err := vrpc.Dial("tcp", pki.FirstServer(), runtime.NumCPU())
	if err != nil {
		log.Fatalf("vrpc.Dial: %s", err)
	}

	lastServer, err := vrpc.Dial("tcp", pki.LastServer(), 1)
	if err != nil {
		log.Fatalf("vrpc.Dial: %s", err)
	}

	srv := &server{
		firstServer:   firstServer,
		lastServer:    lastServer,
		connections:   make(map[*connection]bool),
		convoRound:    0,
		convoRequests: make([]*convoReq, 0, 10000),
		dialRound:     0,
		dialRequests:  make([]*dialReq, 0, 10000),
	}

	go srv.convoRoundLoop()
	go srv.dialRoundLoop()

	http.HandleFunc("/ws", srv.wsHandler)

	httpServer := &http.Server{
		Addr: *addr,
	}

	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
