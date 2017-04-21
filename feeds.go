package ssb

import (
	"os"
	"sync/atomic"
	"github.com/go-kit/kit/log"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/boltdb/bolt"
	"github.com/ezdiy/secretstream/secrethandshake"
	"golang.org/x/crypto/ed25519"
)

func itob(v int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	return b
}

func btoi(b []byte) int {
	return int(binary.BigEndian.Uint64(b))
}

type DataStore struct {
	db *bolt.DB

	feedlock sync.Mutex
	feeds    map[Ref]*Feed
	pending map[*Feed]int
	feedq chan *SignedMessage

	Topic *MessageTopic

	PrimaryKey *secrethandshake.EdKeyPair
	PrimaryRef Ref

	extraData     map[string]interface{}
	extraDataLock sync.Mutex
	Log log.Logger

	Keys map[Ref]Signer
}

func (ds *DataStore) ExtraData(name string) interface{} {
	ds.extraDataLock.Lock()
	defer ds.extraDataLock.Unlock()
	return ds.extraData[name]
}

func (ds *DataStore) SetExtraData(name string, data interface{}) {
	ds.extraDataLock.Lock()
	defer ds.extraDataLock.Unlock()
	ds.extraData[name] = data
}

func (ds *DataStore) DB() *bolt.DB {
	return ds.db
}

type Feed struct {
	store *DataStore
	ID    Ref
	Topic *MessageTopic

	latest atomic.Value
	queue []*SignedMessage
}

func (f *Feed) Commit(tx *bolt.Tx, feeds *bolt.Bucket, n int) {
	q := f.queue
	ds := f.store
	last := f.Latest()
	latest := last
	var l log.Logger
	if last == nil {
		l = log.With(ds.Log, "commit", f.ID)
	} else {
		l = log.With(ds.Log, "commit", f.ID, "lseq", last.Sequence, "lts", last.Timestamp, "lhash", last.Key())
	}

	//check hash-commited chain
	idx := -1
	for i := 0; i < n; i++ {
		m := q[i]
		if (m.Author != f.ID) {
			panic("m.Author == feed.ID invariant violation")
		}
		if !m.Verify(l, last) {
			continue
		}
		idx = i
		last = m
	}

	//now tip sig
	if (last != latest) {
		err := last.VerifySignature()
		if err != nil { // fallback
			last = latest
			for ;idx > 0; idx-- {
				if q[idx].VerifySignature() != nil {
					last = q[idx]
					break
				}
			}
		}
	}

	// TODO:
	// break above into pre-commit (parallel) and following into commit (ordered)
	if (last != latest) {
		f.latest.Store(last)
		feed := feeds.Bucket([]byte(f.ID))
		for i := 0; i < idx; i++ {
			m := q[i]
			buf, _ := Encode(m)
			for _, hook := range AddMessageHooks {
				hook(m, tx)
			}
			if (m.Sequence == 1) {
				f.store.Log.Log("newfeed", m.Author)
			}
			feed.Put(itob(m.Sequence), buf)
			f.Topic.Send <- m
		}
	}

	//f.queue = q[n:]
	copy(q, q[n:])
	f.queue = q[:len(q)-n]
}

func (ds *DataStore) feed_collector(txint int) {
	for {
		select {
		case m := <-ds.feedq:
			f := ds.GetFeed(m.Author) // Sender verifies author!
			pending, _ := ds.pending[f]
			ds.pending[f] = pending+1
			f.queue = append(f.queue, m)
		case <-time.After(time.Duration(txint) * time.Millisecond):
			ds.db.Update(func(tx *bolt.Tx) error {
				feeds := tx.Bucket([]byte("feeds"))
				for f, npend := range ds.pending {
					f.Commit(tx, feeds, npend)
					delete(ds.pending, f)
				}
				return nil
			})
		}
	}
}

func OpenDataStore(l *log.Logger, path string, keypair *secrethandshake.EdKeyPair, txint int) (*DataStore, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}
	ds := &DataStore{
		db:        db,
		feeds:     map[Ref]*Feed{},
		pending:   map[*Feed]int{},
		Topic:     NewMessageTopic(),
		extraData: map[string]interface{}{},
		Keys:      map[Ref]Signer{},
		PrimaryKey: keypair,
	}
	if l == nil {
		ds.Log = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	} else {
		ds.Log = *l
	}
	ds.PrimaryRef = Ref("@" + base64.StdEncoding.EncodeToString(ds.PrimaryKey.Public[:]) + ".ed25519")
	ds.Keys[Ref("@"+base64.StdEncoding.EncodeToString(ds.PrimaryKey.Public[:])+".ed25519")] = &SignerEd25519{ed25519.PrivateKey(ds.PrimaryKey.Secret[:])}
	if txint < 10 {
		txint = 100
	}
	go ds.feed_collector(txint)
	return ds, nil
}

func (ds *DataStore) GetFeed(feedID Ref) *Feed {
	ds.feedlock.Lock()
	defer ds.feedlock.Unlock()
	if feed, ok := ds.feeds[feedID]; ok {
		return feed
	}
	if feedID.Type() != RefFeed {
		ds.Log.Log("feed", feedID, "error", "invalid ref")
		return nil
	}
	feed := &Feed{store: ds, ID: feedID, Topic: NewMessageTopic()}
	feed.Topic.Register(ds.Topic.Send, true)
	ds.feeds[feedID] = feed

	ds.db.Update(func(tx *bolt.Tx) error {
		feeds, _ := tx.CreateBucketIfNotExists([]byte("feeds"))
		fb, _ := feeds.CreateBucketIfNotExists([]byte(feed.ID))
		fb.FillPercent = 1
		return nil
	})
	feed.latest.Store(feed.LatestCommited())
	return feed
}

var AddMessageHooks = map[string]func(m *SignedMessage, tx *bolt.Tx) error{}

func (ds *DataStore) AddMessage(m *SignedMessage) error {
	ds.feedq <- m
	return nil
}

func (f *Feed) Latest() (m *SignedMessage) {
	return f.latest.Load().(*SignedMessage)
}

func (f *Feed) AddMessage(m *SignedMessage) error {
	if m.Author != f.ID {
		return fmt.Errorf("Wrong feed")
	}
	return f.store.AddMessage(m)
}

func (f *Feed) PublishMessage(body interface{}) error {
	content, _ := json.Marshal(body)
	return f.PublishMessageJSON(content)
}

func (f *Feed) PublishMessageJSON(content json.RawMessage) error {
	m := &Message{
		Author:    f.ID,
		Timestamp: float64(time.Now().UnixNano() / int64(time.Millisecond)),
		Hash:      "sha256",
		Content:   content,
		Sequence:  1,
	}

	if l := f.Latest(); l != nil {
		key := l.Key()
		m.Previous = &key
		m.Sequence = l.Sequence + 1
		for m.Timestamp <= l.Timestamp {
			m.Timestamp += 1
		}
	}

	signer := f.store.Keys[f.ID]
	if signer == nil {
		return fmt.Errorf("Cannot sign message without signing key for feed")
	}
	sm := m.Sign(signer)

	err := f.AddMessage(sm)
	if err != nil {
		return err
	}

	return nil
}

func (f *Feed) LatestCommited() (m *SignedMessage) {
       f.store.db.View(func(tx *bolt.Tx) error {
               FeedsBucket := tx.Bucket([]byte("feeds"))
               if FeedsBucket == nil {
                       return nil
               }
               FeedBucket := FeedsBucket.Bucket([]byte(f.ID))
               if FeedBucket == nil {
                       return nil
               }
               cur := FeedBucket.Cursor()
               _, val := cur.Last()
               json.Unmarshal(val, &m)
               return nil
       })
       return
}

var ErrLogClosed = errors.New("LogClosed")

func (f *Feed) Log(seq int, live bool) chan *SignedMessage {
	c := make(chan *SignedMessage, 10)
	go func() {
		liveChan := make(chan *SignedMessage, 10)
		if live {
			f.Topic.Register(liveChan, false)
		} else {
			close(liveChan)
		}
		err := f.store.db.View(func(tx *bolt.Tx) error {
			FeedsBucket := tx.Bucket([]byte("feeds"))
			if FeedsBucket == nil {
				return nil
			}
			FeedBucket := FeedsBucket.Bucket([]byte(f.ID))
			if FeedBucket == nil {
				return nil
			}
			err := FeedBucket.ForEach(func(k, v []byte) error {
				var m *SignedMessage
				json.Unmarshal(v, &m)
				if m.Sequence < seq {
					return nil
				}
				seq = m.Sequence
				select {
				case c <- m:
				case <-time.After(100 * time.Millisecond):
					close(c)
					return ErrLogClosed
				}
				return nil
			})
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return
		}
		if (live) {
			for m := range liveChan {
				if m.Sequence < seq {
					continue
				}
				seq = m.Sequence
				c <- m
			}
		}
		close(c)
	}()
	return c
}
