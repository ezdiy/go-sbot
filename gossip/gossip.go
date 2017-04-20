package gossip

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
	"net"

	"github.com/boltdb/bolt"

	"github.com/ezdiy/go-ssb"
	"github.com/ezdiy/go-ssb/graph"
	"github.com/ezdiy/secretstream"
	"github.com/go-kit/kit/log"
	"github.com/ezdiy/go-muxrpc"
)

type Pub struct {
	Link ssb.Ref `json:"link"`
	Host string  `json:"host"`
	Port int     `json:"port"`
}

type PubAnnounce struct {
	ssb.MessageBody
	Pub Pub `json:"pub"`
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

	// maps pub -> didweinitiate?
	conns := make(map[ssb.Ref]bool)
	sbotAppKey, _ := base64.StdEncoding.DecodeString("1KHLiKZvAvjbY1ziZEHMXawbCEIM6qwjCDm3VYRan/s=")

	if addr != "" {
		go func() {
			sss, _ := secretstream.NewServer(*ds.PrimaryKey, sbotAppKey)
			listener, _ := sss.Listen("tcp", addr)
			fmt.Println("Listening on ",addr)
			for {
				conn, err := listener.Accept()
				if err != nil {
					fmt.Println("error accepting connection: ",err)
					continue
				}
				go func() {
					caller,_ := ssb.NewRef(ssb.RefFeed, ssb.RefAlgoEd25519, conn.(secretstream.Conn).GetRemote())
					fmt.Println("Accepted connection from ", caller)

					lock.Lock()
					is_client, ok := conns[caller]
					if !ok {
						conns[caller] = false
					}
					lock.Unlock()
					defer conn.Close()
					if ok && is_client {
						fmt.Println("Already talking to ", caller, " (we connected first), dropping")
						return
					} else {
						handle(ds, conn, caller)
					}
					lock.Lock()
					delete(conns, caller)
					lock.Unlock()
				}()
			}
		}()
	}

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
			fmt.Println("tick: ",len(pubList))

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
				fmt.Println("Connecting to ",pub)
				d, err := ssc.NewDialer(pubKey)
				if err == nil {
					conn, err := d("tcp", fmt.Sprintf("%s:%d", pub.Host, pub.Port))
					if err == nil {
						handle(ds, conn, pub.Link)
						conn.Close()
					} else {
						fmt.Println("Conn failed",err)
					}
				} else {
					fmt.Println("dialer failed", err)
				}

				lock.Lock();
				delete(conns, pub.Link)
				lock.Unlock()
			}()
		}
	}()
}

func get_feed(ds *ssb.DataStore, mux *muxrpc.Client, feed ssb.Ref) {
	reply := make(chan *ssb.SignedMessage)
	f := ds.GetFeed(feed)
	seq := 0
	if f.Latest() != nil {
		seq = f.Latest().Sequence + 1
	}
	go func() {
		err := mux.Source("createHistoryStream", reply,
			map[string]interface{}{"id": f.ID, "seq": seq, "live": true, "keys": false})
		if err != nil {
			fmt.Println("err",err)
		}
		close(reply)
	}()
	for m := range reply {
		fmt.Println("repl",m)
		f.AddMessage(m)
	}
}

func AskForFeeds(ds *ssb.DataStore, mux *muxrpc.Client, peer ssb.Ref) {
	for feed := range graph.GetMultiFollows(ds, map[ssb.Ref]int{peer:0, ds.PrimaryRef:0}, 2) {
		go get_feed(ds, mux, feed)
	}
}

func InitMux(ds *ssb.DataStore, conn net.Conn, peer ssb.Ref) *muxrpc.Client {
	mux := muxrpc.NewClient(log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout)), conn)
	mux.HandleSource("createHistoryStream", func(rm json.RawMessage) chan interface{} {
		fmt.Println("rm",string(rm[:]))
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
				if (m == nil) {
					c <- map[string]bool{"sync": true}
				} else {
					c <- m
				}
			}
			close(c)
		}()
		return c
	})
	return mux
}

func Replicator(ds *ssb.DataStore, conn net.Conn, peer ssb.Ref) {
	mux := InitMux(ds, conn, peer)
	fmt.Println("Askin")
	AskForFeeds(ds, mux, peer)
	fmt.Println("handling")
	mux.Handle()
	fmt.Println("handled")
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
	Gossip(ds, addr, Replicator, 1, 5)
}

