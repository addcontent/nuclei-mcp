package cache

import (
	"fmt"
	"testing"
	"time"
)

func TestPutLookupGet(t *testing.T) {
	s := New(true, time.Hour, 10)
	r := s.Put("k", ScanResult{Target: "example.com", ScanTime: time.Now()})
	if r.ID == "" {
		t.Fatal("Put must assign an ID")
	}
	if got, ok := s.Lookup("k"); !ok || got.ID != r.ID {
		t.Fatalf("Lookup = %+v, %v", got, ok)
	}
	if got, ok := s.Get(r.ID); !ok || got.Target != "example.com" {
		t.Fatalf("Get = %+v, %v", got, ok)
	}
	if _, ok := s.Lookup("other"); ok {
		t.Fatal("unexpected hit")
	}
}

func TestExpiryStopsReuseButKeepsResult(t *testing.T) {
	s := New(true, time.Minute, 10)
	now := time.Now()
	s.now = func() time.Time { return now }
	r := s.Put("k", ScanResult{ScanTime: now})
	s.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, ok := s.Lookup("k"); ok {
		t.Fatal("expired result reused")
	}
	if _, ok := s.Get(r.ID); !ok {
		t.Fatal("expired result must stay readable by ID until evicted")
	}
}

func TestReuseDisabled(t *testing.T) {
	s := New(false, time.Hour, 10)
	r := s.Put("k", ScanResult{ScanTime: time.Now()})
	if _, ok := s.Lookup("k"); ok {
		t.Fatal("reuse disabled but Lookup hit")
	}
	if _, ok := s.Get(r.ID); !ok {
		t.Fatal("results must be kept even with reuse disabled")
	}
}

func TestPartialNeverReused(t *testing.T) {
	s := New(true, time.Hour, 10)
	s.Put("k", ScanResult{ScanTime: time.Now(), Partial: true})
	if _, ok := s.Lookup("k"); ok {
		t.Fatal("partial result reused")
	}
}

func TestMaxSizeEvictsOldest(t *testing.T) {
	s := New(true, time.Hour, 3)
	base := time.Now()
	var ids []string
	for i := 0; i < 5; i++ {
		r := s.Put(fmt.Sprintf("k%d", i), ScanResult{ScanTime: base.Add(time.Duration(i) * time.Second)})
		ids = append(ids, r.ID)
	}
	if s.Len() != 3 {
		t.Fatalf("Len = %d, want 3", s.Len())
	}
	if _, ok := s.Get(ids[0]); ok {
		t.Error("oldest result not evicted")
	}
	if _, ok := s.Lookup("k0"); ok {
		t.Error("evicted result still reusable")
	}
	recent := s.Recent()
	if recent[0].ID != ids[4] || recent[2].ID != ids[2] {
		t.Errorf("Recent not newest first: %v", []string{recent[0].ID, recent[1].ID, recent[2].ID})
	}
}

func TestConcurrentUse(t *testing.T) {
	s := New(true, time.Hour, 50)
	done := make(chan struct{})
	for g := 0; g < 8; g++ {
		go func(g int) {
			for i := 0; i < 200; i++ {
				key := fmt.Sprintf("k%d", i%20)
				s.Put(key, ScanResult{ScanTime: time.Now()})
				s.Lookup(key)
				s.Recent()
			}
			done <- struct{}{}
		}(g)
	}
	for g := 0; g < 8; g++ {
		<-done
	}
}
