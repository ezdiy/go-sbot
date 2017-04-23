package ssb

import (
	"os"
	"sync/atomic"
	"github.com/go-kit/kit/log"
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

type Pointer struct {
	Author   Ref
	Sequence int
}

/*
var known map[string]bool

func init() {
	known = make(map[string]bool)
}
*/

func (f *Feed) Commit(tx *bolt.Tx, dbfeeds *bolt.Bucket, dblog *bolt.Bucket, dbptr *bolt.Bucket, n int) {
	q := f.queue
	last := f.Latest()
	latest := last
	var l log.Logger
	//l = log.With(ds.Log, "commit", f.ID)

	//check hash-commited chain
	idx := -1
	delta := 0
	for i := 0; i < n; i++ {
		m := q[i]
		if (m.Author != f.ID) {
			panic("m.Author == feed.ID invariant violation")
		}
		if m.Verify(last) < 0 {
			delta++ // omit
			continue
		}
		idx = i-delta
		q[idx] = m
		last = m
	}
	n -= delta

	//now tip sig
	if (last != latest) {
		err := last.VerifySignature()
		if err != nil { // fallbacka
			f.store.Log.Log("hashfail", last.Author, "seq", last.Sequence)
			//fmt.Println("fork; retracing")
			last = latest
			for ;idx >= 0; idx-- {
				if q[idx].VerifySignature() != nil {
					last = q[idx]
					break
				}
			}
			f.store.Log.Log("rollback", last.Author, "seq", last.Sequence)
		}
	}

	// TODO:
	// break above into pre-commit (parallel) and following into commit (ordered)
	if (last != latest) {
		fb, _ := dbfeeds.CreateBucketIfNotExists(f.ID.DBKey())
		fb.FillPercent = 1
		fl, _ := fb.CreateBucketIfNotExists([]byte("log"))
		fl.FillPercent = 1

		for i := 0; i <= idx; i++ {
			m := q[i]
			buf, _ := Encode(m)
			if (m.Sequence == 1) {
				/*
				if (known[m.Author.String()]) {
					for x, y := range(q) {
						fmt.Println(x,y.Sequence)
					}
					panic("db inconsistent"+f.ID.String())
				}
				known[m.Author.String()] = true*/
				f.store.Log.Log("newfeed", m.Author)
			}

			fl.Put(itob(m.Sequence), buf)

			seq, _ := dblog.NextSequence()
			dblog.Put(itob(int(seq)), m.Key().DBKey())

			ptr := Pointer{Author: m.Author, Sequence: m.Sequence}
			buf, _ = json.Marshal(ptr)
			dbptr.Put(m.Key().DBKey(), buf)

			for module, hook := range AddMessageHooks {
				err := hook(m, tx)
				if err != nil {
					l.Log("hook", module, "error", err)
				}
			}

			f.Topic.Send <- m
		}
		f.latest.Store(last)
	}

	//f.queue = q[n:]

	//copy(q, q[n:])
	//f.queue = q[:len(q)-n]

	remain := len(q) - n
	f.queue = make([](*SignedMessage), remain)
	copy(f.queue, q[n:])
}

func (ds *DataStore) BatchCommit() {
	ds.db.Update(func(tx *bolt.Tx) error {
		dbfeeds, _ := tx.CreateBucketIfNotExists([]byte("feeds"))
		dbfeeds.FillPercent = 1
		dblog, _ := tx.CreateBucketIfNotExists([]byte("log"))
		dblog.FillPercent = 1
		dbptr, _ := tx.CreateBucketIfNotExists([]byte("pointer"))

		for f, npend := range ds.pending {
			f.Commit(tx, dbfeeds, dblog, dbptr, npend)
			delete(ds.pending, f)
		}
		return nil
	})
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
			ds.BatchCommit()
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
		feedq:	   make(chan *SignedMessage),
		extraData: map[string]interface{}{},
		Keys:      map[Ref]Signer{},
		PrimaryKey: keypair,
	}
	if l == nil {
		ds.Log = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	} else {
		ds.Log = *l
	}
	ds.db.Update(func(tx *bolt.Tx) error {
		tx.CreateBucketIfNotExists([]byte("feeds"))
		return nil
	})
	ds.PrimaryRef, _ = NewRef(RefFeed, ds.PrimaryKey.Public[:], RefAlgoEd25519)
	ds.Keys[ds.PrimaryRef] = &SignerEd25519{ed25519.PrivateKey(ds.PrimaryKey.Secret[:])}
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
	if feedID.Type != RefFeed {
		ds.Log.Log("feed", feedID, "error", "invalid ref")
		return nil
	}
	feed := &Feed{store: ds, ID: feedID, Topic: NewMessageTopic()}
	feed.Topic.Register(ds.Topic.Send, true)
	ds.feeds[feedID] = feed
	feed.latest.Store(feed.LatestCommited())
	return feed
}

func (ds *DataStore) Get(tx *bolt.Tx, post Ref) (m *SignedMessage) {
	var err error
	if tx == nil {
		tx, err = ds.db.Begin(false)
		if err != nil {
			return
		}
		defer tx.Rollback()
	}
	PointerBucket := tx.Bucket([]byte("pointer"))
	if PointerBucket == nil {
		return
	}
	pdata := PointerBucket.Get(post.DBKey())
	if pdata == nil {
		return
	}
	p := Pointer{}
	json.Unmarshal(pdata, &p)
	FeedsBucket := tx.Bucket([]byte("feeds"))
	if FeedsBucket == nil {
		return
	}
	FeedBucket := FeedsBucket.Bucket(p.Author.DBKey())
	if FeedBucket == nil {
		return
	}
	LogBucket := FeedBucket.Bucket([]byte("log"))
	if LogBucket == nil {
		return
	}
	msgdata := LogBucket.Get(itob(p.Sequence))
	if msgdata == nil {
		return
	}
	json.Unmarshal(msgdata, &m)
	return
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

var RebuildClearHooks = map[string]func(tx *bolt.Tx) error{}

func (ds *DataStore) RebuildAll() {
	fmt.Println("Starting rebuild of all indexes")
	count := 0
	ds.db.Update(func(tx *bolt.Tx) error {
		for module, hook := range RebuildClearHooks {
			err := hook(tx)
			if err != nil {
				return fmt.Errorf("Bolt %s hook: %s", module, err)
			}
		}

		LogBucket, err := tx.CreateBucketIfNotExists([]byte("log"))
		if err != nil {
			return err
		}
		cursor := LogBucket.Cursor()
		_, v := cursor.First()
		for v != nil {
			for module, hook := range AddMessageHooks {
				err = hook(ds.Get(tx, DBRef(v)), tx)
				if err != nil {
					return fmt.Errorf("Bolt %s hook: %s", module, err)
				}
			}
			count++
			_, v = cursor.Next()
		}
		return nil
	})
	fmt.Println("Finished rebuild of all modules")
	fmt.Println("Reindexed", count, "posts")
}

func (ds *DataStore) Rebuild(module string) {
	fmt.Println("Starting rebuild of", module)
	count := 0
	ds.db.Update(func(tx *bolt.Tx) error {
		if clear, ok := RebuildClearHooks[module]; ok {
			err := clear(tx)
			if err != nil {
				return err
			}
		}

		LogBucket, err := tx.CreateBucketIfNotExists([]byte("log"))
		if err != nil {
			return err
		}
		cursor := LogBucket.Cursor()
		_, v := cursor.First()
		for v != nil {
			AddMessageHooks[module](ds.Get(tx, DBRef(v)), tx)
			count++
			_, v = cursor.Next()
		}
		return nil
	})
	fmt.Println("Finished rebuild of", module)
	fmt.Println("Reindexed", count, "messages")
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

	// FIXME: this is racy, the queue might be long ahead of us
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
		FeedBucket := FeedsBucket.Bucket(f.ID.DBKey())
		if FeedBucket == nil {
			return nil
		}
		FeedLogBucket := FeedBucket.Bucket([]byte("log"))
		if FeedLogBucket == nil {
			return nil
		}
		cur := FeedLogBucket.Cursor()
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
			FeedBucket := FeedsBucket.Bucket(f.ID.DBKey())
			if FeedBucket == nil {
				return nil
			}
			FeedLogBucket := FeedBucket.Bucket([]byte("log"))
			if FeedLogBucket == nil {
				return nil
			}
			err := FeedLogBucket.ForEach(func(k, v []byte) error {
				var m *SignedMessage
				json.Unmarshal(v, &m)
				if m.Sequence < seq {
					return nil
				}
				seq = m.Sequence
				select {
				case c <- m:
				case <-time.After(1000 * time.Millisecond):
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
