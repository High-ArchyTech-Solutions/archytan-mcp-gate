// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate

import "sync"

// callQueue is an unbounded FIFO. Pushing never blocks, which is the
// point: the host reader must keep reading stdin while a gated call waits
// on the network, or a notifications/cancelled would sit unread in the
// pipe until it no longer mattered.
type callQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	items  []*call
	closed bool
}

func newCallQueue() *callQueue {
	q := &callQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *callQueue) push(c *call) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return false
	}
	q.items = append(q.items, c)
	q.cond.Signal()
	return true
}

// pop blocks until a call is available or the queue is closed and empty.
func (q *callQueue) pop() (*call, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && !q.closed {
		q.cond.Wait()
	}
	if len(q.items) == 0 {
		return nil, false
	}
	c := q.items[0]
	q.items[0] = nil
	q.items = q.items[1:]
	return c, true
}

func (q *callQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.cond.Broadcast()
	q.mu.Unlock()
}
