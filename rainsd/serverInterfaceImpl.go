package rainsd

import (
	"bufio"
	"container/list"
	"crypto/rand"
	"net"
	"rains/utils/cache"
	"sync"

	"fmt"

	"rains/rainslib"

	"time"

	log "github.com/inconshreveable/log15"
)

type newLineFramer struct {
	Scanner   *bufio.Scanner
	firstCall bool
}

func (f newLineFramer) Frame(msg []byte) ([]byte, error) {
	return append(msg, "\n"...), nil
}

func (f *newLineFramer) Deframe() bool {
	if f.firstCall {
		f.Scanner.Split(bufio.ScanLines)
		f.firstCall = false
	}
	return f.Scanner.Scan()
}

func (f newLineFramer) Data() []byte {
	return f.Scanner.Bytes()
}

//PRG pseudo random generator
type PRG struct{}

func (prg PRG) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}

/*//TODO CFE replace this with an own implementation
//LRUCache is a concurrency safe cache with a least recently used eviction strategy
type LRUCache struct {
	Cache *lru.Cache
}

//New creates a lru cache with the given parameters
func (c *LRUCache) New(params ...interface{}) error {
	var err error
	c.Cache, err = lru.New(params[0].(int))
	return err
}

//NewWithEvict creates a lru cache with the given parameters and an eviction callback function
func (c *LRUCache) NewWithEvict(onEvicted func(key interface{}, value interface{}), params ...interface{}) error {
	var err error
	c.Cache, err = lru.NewWithEvict(params[0].(int), onEvicted)
	return err
}

//Add adds a value to the cache. If the cache is full the least recently used element will be replaced. Returns true if an eviction occurred.
func (c *LRUCache) Add(key, value interface{}) bool {
	return c.Cache.Add(key, value)
}

//Contains checks if a key is in the cache, without updating the recentness or deleting it for being stale.
func (c *LRUCache) Contains(key interface{}) bool {
	return c.Cache.Contains(key)
}

//Get returns the key's value from the cache. The boolean value is false if there exist no element with the given key in the cache
func (c *LRUCache) Get(key interface{}) (interface{}, bool) {
	return c.Cache.Get(key)
}

//Keys returns a slice of the keys in the cache sorted from oldest to newest
func (c *LRUCache) Keys() []interface{} {
	return c.Cache.Keys()
}

//Len returns the number of elements in the cache.
func (c *LRUCache) Len() int {
	return c.Cache.Len()
}

//Remove deletes the given key value pair from the cache
func (c *LRUCache) Remove(key interface{}) {
	c.Cache.Remove(key)
}

//RemoveWithStrategy deletes the least recently used key value pair from the cache
func (c *LRUCache) RemoveWithStrategy() {
	c.Cache.RemoveOldest()
}*/

/*
 *	Connection cache implementation
 */
type connectionCacheImpl struct {
	cache *cache.Cache
}

func (c *connectionCacheImpl) Add(fourTuple string, conn net.Conn) bool {
	return c.cache.Add(conn, false, "", fourTuple)
}

func (c *connectionCacheImpl) Get(fourTuple string) (net.Conn, bool) {
	if v, ok := c.cache.Get("", fourTuple); ok {
		if val, ok := v.(net.Conn); ok {
			return val, true
		}
		log.Warn("Cache entry is not of type net.Conn", "type", fmt.Sprintf("%T", v))
	}
	return nil, false
}

func (c *connectionCacheImpl) Len() int {
	return c.cache.Len()
}

/*
 *	Capability cache implementation
 */
type capabilityCacheImpl struct {
	connInfoToCap *cache.Cache
	hashToCap     *cache.Cache
}

func (c *capabilityCacheImpl) Add(connInfo ConnInfo, capabilities []rainslib.Capability) bool {
	//FIXME CFE take a SHA-256 hash of the CBOR byte stream derived from normalizing such an array by sorting it in lexicographically increasing order,
	//then serializing it and add it to the cache
	return c.connInfoToCap.Add(capabilities, false, "", connInfo.IPAddrAndPort())
}

func (c *capabilityCacheImpl) Get(connInfo ConnInfo) ([]rainslib.Capability, bool) {
	if v, ok := c.connInfoToCap.Get("", connInfo.IPAddrAndPort()); ok {
		if val, ok := v.([]rainslib.Capability); ok {
			return val, true
		}
		log.Warn("Cache entry is not of type []rainslib.Capability", "type", fmt.Sprintf("%T", v))
	}
	return nil, false
}

func (c *capabilityCacheImpl) GetFromHash(hash []byte) ([]rainslib.Capability, bool) {
	if v, ok := c.hashToCap.Get("", string(hash)); ok {
		if val, ok := v.([]rainslib.Capability); ok {
			return val, true
		}
		log.Warn("Cache entry is not of type []rainslib.Capability", "type", fmt.Sprintf("%T", v))
	}
	return nil, false
}

/*
 * Key cache implementation
 */
type keyCacheImpl struct {
	cache *cache.Cache
}

//Add adds the public key to the cash.
//Returns true if the given public key was successfully added. If it was not possible to add the key it return false.
//If the cache is full it removes all public keys from a keyCacheKey entry according to least recently used
//The cache makes sure that only a small limited amount of public keys (e.g. 3) can be stored associated with a keyCacheKey
//If the internal flag is set, this key will only be removed after it expired.
func (c *keyCacheImpl) Add(key keyCacheKey, value rainslib.PublicKey, internal bool) bool {
	//TODO add an getOrAdd method to the cache (locking must then be changed.)
	list := &pubKeyList{maxElements: 3, keys: list.New()}
	c.cache.Add(list, internal, key.context, key.zone, key.keyAlgo.String())
	v, ok := c.cache.Get(key.context, key.zone, key.keyAlgo.String())
	if !ok {
		return false
	}
	if list, ok := v.(*pubKeyList); ok {
		list.Add(value)
	}
	log.Error(fmt.Sprintf("Element in cache is not of type *pubKeyList. Got type=%T", v))
	return false
}

//Get returns a valid public key matching the given keyCacheKey. It returns false if there exists no valid public key in the cache.
//Get must always check the validity period of the public key before returning.
func (c *keyCacheImpl) Get(key keyCacheKey) (rainslib.PublicKey, bool) {
	v, ok := c.cache.Get(key.context, key.zone, key.keyAlgo.String())
	if !ok {
		return rainslib.PublicKey{}, false
	}
	list := v.(publicKeyList)
	k, ok := list.Get()
	if !ok {
		return rainslib.PublicKey{}, false
	}
	return k, true
}

//RemoveExpiredKeys deletes a public key value pair from the cache if it is expired
func (c *keyCacheImpl) RemoveExpiredKeys() {
	keys := c.cache.Keys()
	for _, key := range keys {
		v, ok := c.cache.Get(key[0], key[1])
		if ok {
			list := v.(publicKeyList)
			list.RemoveExpiredKeys()
		}
	}
}

//pubKeyList contains some public keys which can be modified concurrently. There are at most maxElements in the list.
type pubKeyList struct {
	//maxElements are the maximal number of elements in the list
	maxElements int
	//mux must always be called when accessing keys list.
	mux sync.RWMutex
	//keys contains public keys
	keys *list.List
}

//Add adds a public key to the list. If specified maximal list length is reached it removes the least recently used element.
func (l *pubKeyList) Add(key rainslib.PublicKey) {
	l.mux.Lock()
	defer l.mux.Unlock()
	l.keys.PushFront(key)
	if l.keys.Len() > l.maxElements {
		l.keys.Remove(l.keys.Back())
	}
}

//Get returns the first valid public key in the list. Returns false if there is no valid public key.
func (l *pubKeyList) Get() (rainslib.PublicKey, bool) {
	l.mux.RLock()
	defer l.mux.RUnlock()
	for e := l.keys.Front(); e != nil; e = e.Next() {
		key := e.Value.(rainslib.PublicKey)
		if key.ValidFrom < time.Now().Unix() && key.ValidUntil > time.Now().Unix() {
			l.keys.MoveToFront(e)
			return key, true
		}
	}
	return rainslib.PublicKey{}, false
}

//RemoveExpiredKeys deletes all expired keys from the list.
func (l *pubKeyList) RemoveExpiredKeys() {
	l.mux.Lock()
	defer l.mux.Unlock()
	for e := l.keys.Front(); e != nil; e = e.Next() {
		key := e.Value.(rainslib.PublicKey)
		if key.ValidUntil < time.Now().Unix() {
			l.keys.Remove(e)
		}
	}
}
