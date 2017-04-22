package gossip

import (
	//"runtime"
	"fmt"
	"github.com/pkg/errors"
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

type Pub struct {
	Host string  `json:"host"`
	Port int     `json:"port"`
	Link ssb.Ref `json:"key"`
}

type PubAnnounce struct {
	ssb.MessageBody
	Pub Pub `json:"address"`
}


func AddPub(ds *ssb.DataStore, pb Pub) {
	ds.DB().Update(func(tx *bolt.Tx) error {
		PubBucket, err := tx.CreateBucketIfNotExists([]byte("pubs"))
		if err != nil {
			return err
		}
		buf, _ := json.Marshal(pb)
		PubBucket.Put([]byte(pb.Link), buf)
		return nil
	})
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
			PubBucket.Put([]byte(mbp.Pub.Link), buf)
			return nil
		}
		return nil
	}
	ssb.MessageTypes["pub"] = func() interface{} {
		return &PubAnnounce{}
	}
}

type Handler func(*ssb.DataStore, net.Conn, ssb.Ref)
func Gossip(ds *ssb.DataStore, addr string, handle Handler, cps int, limit int) {
	var lock  sync.Mutex
	netin := log.With(ds.Log, "gossip", "incoming")
	netout := log.With(ds.Log, "gossip", "outgoing")

	// maps pub -> didweinitiate?
	conns := make(map[ssb.Ref]bool)
	sbotAppKey, _ := base64.StdEncoding.DecodeString("1KHLiKZvAvjbY1ziZEHMXawbCEIM6qwjCDm3VYRan/s=")

	if addr != "" {
		go func() {
			sss, _ := secretstream.NewServer(*ds.PrimaryKey, sbotAppKey)
			listener, _ := sss.Listen("tcp", addr)
			netin.Log("Listening on ",addr)
			for {
				conn, err := listener.Accept()
				if err != nil {
					continue
				}
				go func() {
					caller,_ := ssb.NewRef(ssb.RefFeed, ssb.RefAlgoEd25519, conn.(secretstream.Conn).GetRemote())
					lock.Lock()
					is_client, ok := conns[caller]
					if !ok {
						conns[caller] = false
					}
					lock.Unlock()
					defer conn.Close()
					if ok && is_client {
						netin.Log("already", caller)
						return
					} else {
						netin.Log("accept", caller)
						handle(ds, conn, caller)
					}
					lock.Lock()
					delete(conns, caller)
					lock.Unlock()
					netin.Log("disconnect", caller)
				}()
			}
		}()
	}
/*
	go func() {
		t := time.NewTicker(time.Duration(10)*time.Second)
		for range t.C {
			ds.Log.Log("gc","start")
			runtime.GC()
			ds.Log.Log("gc","stop")
		}
	}()
*/
	go func() {
		ssc, _ := secretstream.NewClient(*ds.PrimaryKey, sbotAppKey)
		var pubList []*Pub
		t := time.NewTicker(time.Duration(cps)*time.Second)
		for range t.C {
			if len(conns) > limit {
				continue
			}
			if len(pubList) == 0 {
				pubList = GetPubs(ds)
			}
			if len(pubList) == 0 {
				continue
			}

			pub := pubList[0]
			pubList = pubList[1:]
			var pubKey [32]byte
			rawpubKey := pub.Link.Raw()
			copy(pubKey[:], rawpubKey)

			go func() {
				lock.Lock();
				_, ok := conns[pub.Link]
				if !ok { conns[pub.Link] = true }
				lock.Unlock()
				if ok { return }
				d, err := ssc.NewDialer(pubKey)
				if err == nil {
					conn, err := d("tcp", fmt.Sprintf("%s:%d", pub.Host, pub.Port))
					if err == nil {
						netout.Log("connect", pub.Link)
						handle(ds, conn, pub.Link)
						conn.Close()
					} else {
						netout.Log("connect",pub.Link,"error", errors.Wrap(err, "dialer: can't dial"))
					}
				} else {
					netout.Log("connect",pub.Link,"error", errors.Wrap(err, "shs: can't build dialer"))
				}
				lock.Lock();
				delete(conns, pub.Link)
				lock.Unlock()
				netout.Log("disconnect", pub.Link)
			}()
		}
	}()
}

func get_feed(ds *ssb.DataStore, mux *muxrpc.Client, feed ssb.Ref, peer ssb.Ref) {
	//fmt.Println("asking for", feed)
	f := ds.GetFeed(feed)
	if f == nil {
		//fmt.Println("didnt get", feed)
		return
	}
	reply := make(chan *ssb.SignedMessage)
	seq := 0
	if m := f.Latest(); m != nil {
		seq = m.Sequence + 1
	}
	go func() {
		err := mux.Source("createHistoryStream", reply,
			map[string]interface{}{"id": f.ID, "seq": seq, "live": true, "keys": false})
		if err != nil {
			ds.Log.Log("getfeed", feed, "error", err)
		}
		close(reply)
	}()
	for m := range reply {
		//fmt.Println("got")
		// TODO: Check if this is faster than checking on the other end
		if latest := f.Latest(); latest != nil {
			if latest.Sequence >= m.Sequence {
				//fmt.Println("above seq")
				continue
			}
		}
		f.AddMessage(m)
		//fmt.Println("done")
	}
}

func AskForFeeds(ds *ssb.DataStore, mux *muxrpc.Client, peer ssb.Ref) {
	for feed := range graph.GetMultiFollows(ds, map[ssb.Ref]int{peer:0, ds.PrimaryRef:0}, 2) {
		go get_feed(ds, mux, feed, peer)
	}
}

func InitMux(ds *ssb.DataStore, conn net.Conn, peer ssb.Ref) *muxrpc.Client {
	mux := muxrpc.NewClient(ds.Log, conn)
	mux.HandleSource("createHistoryStream", func(rm json.RawMessage) chan interface{} {
		params := struct {
			Id   ssb.Ref `json:"id"`
			Seq  int     `json:"seq"`
			Live bool    `json:"live"`
		}{
			"",
			0,
			false,
		}
		args := []interface{}{&params}
		json.Unmarshal(rm, &args)
		f := ds.GetFeed(params.Id)
		c := make(chan interface{})
		go func() {
			for m := range f.Log(params.Seq, params.Live) {
				c <- m
			}
		}()
		return c
	})
	return mux
}

func Replicator(ds *ssb.DataStore, conn net.Conn, peer ssb.Ref) {
	mux := InitMux(ds, conn, peer)
	AskForFeeds(ds, mux, peer)
	mux.Handle()
}


func GetPubs(ds *ssb.DataStore) (pds []*Pub) {
	ds.DB().View(func(tx *bolt.Tx) error {
		PubBucket := tx.Bucket([]byte("pubs"))
		if PubBucket == nil {
			return nil
		}
		PubBucket.ForEach(func(k, v []byte) error {
			var pd *Pub
			json.Unmarshal(v, &pd)
			pds = append(pds, pd)
			return nil
		})
		return nil
	})
	return
}

func Replicate(ds *ssb.DataStore, addr string) {
	Gossip(ds, addr, Replicator, 1, 100)
}

