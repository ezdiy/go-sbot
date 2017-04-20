package graph

import (
	"encoding/json"

	".."
	"github.com/boltdb/bolt"
)

type Relation struct {
	Following bool
	Blocking  bool
}

type Contact struct {
	ssb.MessageBody
	Contact   ssb.Ref `json:"contact"`
	Following *bool   `json:"following,omitempty"`
	Blocking  *bool   `json:"blocking,omitempty"`
}

func init() {
	ssb.AddMessageHooks["graph"] = handleGraph
	ssb.MessageTypes["contact"] = func() interface{} { return &Contact{} }
}

func handleGraph(m *ssb.SignedMessage, tx *bolt.Tx) error {
	_, mb := m.DecodeMessage()
	if mbc, ok := mb.(*Contact); ok {
		GraphBucket, err := tx.CreateBucketIfNotExists([]byte("graph"))
		if err != nil {
			return err
		}
		FeedBucket, err := GraphBucket.CreateBucketIfNotExists([]byte(m.Author))
		var r Relation
		json.Unmarshal(FeedBucket.Get([]byte(mbc.Contact)), &r)
		if err != nil {
			return err
		}
		if mbc.Following != nil {
			r.Following = *mbc.Following
		}
		if mbc.Blocking != nil {
			r.Blocking = *mbc.Blocking
		}
		buf, _ := json.Marshal(r)
		err = FeedBucket.Put([]byte(mbc.Contact), buf)
		if err != nil {
			return err
		}
	}
	return nil
}
func GetFollows(ds *ssb.DataStore, feed ssb.Ref, depth int) (follows map[ssb.Ref]int) {
	follows = map[ssb.Ref]int{}
	follows[feed] = 0
	GetMultiFollows(ds, follows, depth)
	return
}

func GetMultiFollows(ds *ssb.DataStore, follows map[ssb.Ref]int, depth int) (map[ssb.Ref]int) {
	ds.DB().View(func(tx *bolt.Tx) error {
		GraphBucket := tx.Bucket([]byte("graph"))
		if GraphBucket == nil {
			return nil
		}
		for l1 := 0; l1 < depth; l1++ {
			for k, v := range follows {
				if v == l1 {
					FeedBucket := GraphBucket.Bucket([]byte(k))
					if FeedBucket == nil {
						continue
					}
					FeedBucket.ForEach(func(k, v []byte) error {
						if _, ok := follows[ssb.Ref(k)]; !ok {
							var r Relation
							json.Unmarshal(v, &r)
							if r.Following {
								follows[ssb.Ref(k)] = l1 + 1
							}
						}
						return nil
					})
				}
			}
		}
		return nil
	})
	return follows
}

