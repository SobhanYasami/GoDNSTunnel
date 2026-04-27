package relay

import (
	"testing"
	"time"
)

func TestNonceCacheReplay(t *testing.T) {
	c := NewNonceCache(100 * time.Millisecond)
	defer c.Close()

	if c.SeenAndStore("abc") {
		t.Fatal("first insert should not collide")
	}
	if !c.SeenAndStore("abc") {
		t.Fatal("second insert should collide")
	}
	// After TTL, the cache should accept the nonce again.
	time.Sleep(150 * time.Millisecond)
	if c.SeenAndStore("abc") {
		t.Fatal("expired entry should be re-acceptable")
	}
}

func TestNonceCacheConcurrentDistinct(t *testing.T) {
	c := NewNonceCache(time.Second)
	defer c.Close()

	const N = 1000
	done := make(chan struct{}, N)
	for i := 0; i < N; i++ {
		go func(i int) {
			n := "n" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26))
			_ = c.SeenAndStore(n)
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < N; i++ {
		<-done
	}
}
