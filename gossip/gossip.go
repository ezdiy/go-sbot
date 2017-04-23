// TODO: better err handling

package gossip

import (
	"fmt"
	"time"
	"encoding/base64"
	"encoding/json"
	"sync"
	"net"

	"github.com/boltdb/bolt"

	"github.com/ezdiy/go-ssb"
	"github.com/ezdiy/go-ssb/graph"
	"github.com/ezdiy/secretstream"
	"github.com/ezdiy/go-muxrpc"
	"github.com/go-kit/kit/log"
)
var sbotAppKey, _ = base64.StdEncoding.DecodeString("1KHLiKZvAvjbY1ziZEHMXawbCEIM6qwjCDm3VYRan/s=")

type Pub struct {
	Host string  `json:"host"`
	Port int     `json:"port"`
	Link ssb.Ref `json:"key"`
}

type PubAnnounce struct {
	ssb.MessageBody
	Pub Pub `json:"address"`
}

type Peer struct {
	*muxrpc.Client
	Id ssb.Ref
	g  *Gossip
	lastmsg  int64
	is_ok bool
}

type PubInfo struct {
	*Pub
	backoff  int64
	lastfail int64
	lastgood int64
}

type Gossip struct {
	Store *ssb.DataStore
	Addr  string
	Peers map[string]*Peer
	Pubs  map[string]*PubInfo
	Handle Handler
	Tick  int
	Idle  int
	Limit int
	Timeout int

	sync.Mutex
}

func (g *Gossip) Setup() {
	if g.Handle == nil {
		g.Handle = DefaultHandler
	}
	g.Peers = make(map[string]*Peer)
	g.Pubs = make(map[string]*PubInfo)
	if (g.Limit == 0) { g.Limit = 20 }
	if (g.Tick == 0) { g.Tick = 1 }
	if (g.Idle == 0) { g.Idle = 600 }
	if (g.Timeout == 0) { g.Timeout = 2 }
}

func (g *Gossip) Server() error {
	netin := log.With(g.Store.Log, "gossip", "server")

	addr := g.Addr
	if (addr == "") {
		addr = "0.0.0.0:8008"
	}

	sss, _ := secretstream.NewServer(*g.Store.PrimaryKey, sbotAppKey)
	listener, err := sss.Listen("tcp", addr)
	if err != nil {
		netin.Log("listen", addr, "error", err)
		return err
	}
	netin.Log("listen", addr)

	for {
	conn, err := listener.Accept()
	if err != nil {
		continue
	}
	go func() {
		cid, _ := ssb.NewRef(ssb.RefFeed, conn.(secretstream.Conn).GetRemote(), ssb.RefAlgoEd25519)
		netin.Log("accept", cid)
		if g.NewPeer(conn, cid) {
			netin.Log("already", cid)
		}
	}()
	}
	return nil
}

func (g *Gossip) NewPeer(conn net.Conn, cid ssb.Ref) bool {
	g.Lock()
	if _, ok := g.Peers[cid.Data]; ok  {
		g.Unlock()
		return true
	}

	p := &Peer{Id: cid, g: g}
	g.Peers[cid.Data] = p
	g.Unlock()

	p.Client = muxrpc.NewClient(g.Store.Log, conn)
	g.Handle(p)

	go func() {
		p.Handle()
		g.Lock()
		delete(g.Peers, cid.Data)
		if !p.is_ok {
			g.MarkFail(cid.Data)
		}
		g.Unlock()
		g.Store.Log.Log("gossip","peer","disconnect", cid)
	}()

	return false
}

func (g *Gossip) MarkFail(id string) {
	now := time.Now().Unix()
	if pub, ok := g.Pubs[id]; ok {
		pub.backoff = (pub.backoff + 1) * 2
		pub.lastfail = now
	}
}
func (p *Peer) MarkOK() {
	now := time.Now().Unix()
	p.lastmsg = now
	if (p.is_ok) {
		return
	}
	p.g.Lock()
	p.is_ok = true
	if pub, ok := p.g.Pubs[p.Id.Data]; ok {
		pub.backoff = 0
		pub.lastfail = 0
	}
	p.g.Unlock()
}

func (g *Gossip) Client() {
	netout := log.With(g.Store.Log, "gossip", "client")
	ssc, _ := secretstream.NewClient(*g.Store.PrimaryKey, sbotAppKey)
	last := int64(0)

	for step:=0;true;step++ {
	//println("tick")
	time.Sleep(time.Duration(g.Tick) * time.Second)
	now := time.Now().Unix()

	if last + 30 < now {
		last = now
		g.UpdatePubs()
	}

	var candidate *PubInfo = nil
	cn := now
	g.Lock()
	for id, v := range g.Pubs {
		var vt int64
		if _, ok := g.Peers[id]; ok {
			continue
		}
		if (step%2 == 0) {
			vt = v.lastfail + v.backoff
		} else {
			vt = v.lastgood
		}
		if (vt < cn) {
			candidate = v
			cn = vt
		}
	}
	if (len(g.Peers) > g.Limit) {
		for _, v := range g.Peers {
			if (v.lastmsg + int64(g.Idle) < now) {
				v.Close()
				// handle will delete the peer for us
			}
		}
	}

	g.Unlock()

	if candidate == nil {
		continue
	}

	pub := candidate.Pub
	number := fmt.Sprintf("%s:%d", pub.Host, pub.Port)
	key := pub.Link.Raw()
	var pk [32]byte
	copy(pk[:], key)
	//fmt.Println("dialing", number)
	conn, err := net.DialTimeout("tcp", number, time.Duration(g.Timeout) * time.Second)
	oconn := conn
	if err == nil {
		conn.SetDeadline(time.Now().Add(time.Duration(g.Timeout) * time.Second))
		conn, err = ssc.Dial2(pk, conn)
	}

	if err != nil {
//		netout.Log("connect", pub.Link, "error", err)
		g.Lock()
		g.MarkFail(pub.Link.Data)
		g.Unlock()
		continue
	}
	oconn.SetDeadline(time.Time{})
	candidate.lastgood = now

	netout.Log("connect", pub.Link)
	g.NewPeer(conn, pub.Link)
	}
}

func (p *Peer) FetchFeed(feed ssb.Ref) {
	//fmt.Println("fetching",feed)
	f := p.g.Store.GetFeed(feed)
	if f == nil {
		return
	}
	reply := make(chan *ssb.SignedMessage)
	seq := 0
	if m := f.Latest(); m != nil {
		seq = m.Sequence + 1
	}
	go func() {
		p.Source("createHistoryStream", reply,
			map[string]interface{}{"id": f.ID, "seq": seq, "live": true, "keys": false})
		close(reply)
	}()
	for m := range reply {
		if latest := f.Latest(); latest != nil {
			if latest.Sequence >= m.Sequence {
				continue
			}
		}
		p.MarkOK()
		f.AddMessage(m)
	}
}

func (p *Peer) FetchFollowedFeeds() {
	for feed := range graph.GetMultiFollows(p.g.Store, map[ssb.Ref]int{p.Id:0, p.g.Store.PrimaryRef:0}, 2) {
		go p.FetchFeed(feed)
	}
}

func (g *Gossip) UpdatePubs() {
	g.Lock()
	g.Store.DB().View(func(tx *bolt.Tx) error {
		PubBucket := tx.Bucket([]byte("pubs"))
		if PubBucket == nil {
			return nil
		}
		PubBucket.ForEach(func(k, v []byte) error {
			var pd *Pub
			json.Unmarshal(v, &pd)
			if _, ok := g.Pubs[pd.Link.Data]; !ok {
				g.Pubs[pd.Link.Data] = &PubInfo{Pub: pd}
			}
			return nil
		})
		return nil
	})
	g.Unlock()
	return
}

////////////////////////////////////////////////////////////////////////////////
type Handler func(p *Peer)
func DefaultHandler(p *Peer) {
	p.HandleSource("createHistoryStream", func(rm json.RawMessage) chan interface{} {
		params := struct {
			Id   ssb.Ref `json:"id"`
			Seq  int     `json:"seq"`
			Live bool    `json:"live"`
		}{
			ssb.Ref{},
			0,
			false,
		}
		args := []interface{}{&params}
		json.Unmarshal(rm, &args)
		//fmt.Println("getting feed", params.Id)
		f := p.g.Store.GetFeed(params.Id)
		c := make(chan interface{})
		go func() {
			for m := range f.Log(params.Seq, params.Live) {
				// opportunistic shortcut
				if (p.IsClosed()) {
					break
				}
				p.MarkOK()
				c <- m
			}
			close(c)
		}()
		return c
	})
	p.FetchFollowedFeeds()
}


func Replicate(ds *ssb.DataStore, addr string) {
	gs := &Gossip{Store: ds, Addr: addr}
	gs.Setup()
	go gs.Server()
	gs.Client()
}

func init() {
	ssb.AddMessageHooks["gossip"] = func(m *ssb.SignedMessage, tx *bolt.Tx) error {
		_, mb := m.DecodeMessage()
		if mbp, ok := mb.(*PubAnnounce); ok {
			PubBucket, err := tx.CreateBucketIfNotExists([]byte("pubs"))
			if err != nil {
				return err
			}
			buf, _ := json.Marshal(mbp.Pub)
			PubBucket.Put(mbp.Pub.Link.DBKey(), buf)
			return nil
		}
		return nil
	}
	ssb.MessageTypes["pub"] = func() interface{} {
		return &PubAnnounce{}
	}
}


