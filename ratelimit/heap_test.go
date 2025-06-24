package ratelimit

import (
	"container/heap"
	"testing"
	"time"
)

func TestLRUHeapPushPop(t *testing.T) {
	h := &LRUHeap[string]{}

	now := time.Now()
	entries := []LRULimiter[string]{
		{"a", now.Add(-5 * time.Minute)},
		{"b", now.Add(-3 * time.Minute)},
		{"c", now.Add(-10 * time.Minute)},
		{"d", now.Add(-1 * time.Minute)},
	}

	for _, e := range entries {
		heap.Push(h, e)
	}

	if h.Len() != len(entries) {
		t.Errorf("expected heap size %d, got %d", len(entries), h.Len())
	}

	// Expect items to pop in increasing order of lastUsed (i.e. oldest first)
	expectedOrder := []string{"c", "a", "b", "d"}
	for _, wantKey := range expectedOrder {
		item := heap.Pop(h).(LRULimiter[string])
		if item.key != wantKey {
			t.Errorf("expected key %s, got %s", wantKey, item.key)
		}
	}
}

func TestLRUHeapEmptyPop(t *testing.T) {
	h := &LRUHeap[string]{}
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when popping from empty heap")
		}
	}()
	_ = heap.Pop(h)
}
