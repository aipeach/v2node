package counter

import (
	"strings"
	"sync"
)

type AuditHit struct {
	Email  string
	ListID int
}

type AuditCounter struct {
	mu   sync.Mutex
	hits map[AuditHit]struct{}
}

func NewAuditCounter() *AuditCounter {
	return &AuditCounter{
		hits: make(map[AuditHit]struct{}),
	}
}

func (c *AuditCounter) Mark(email string, listID int) {
	email = strings.TrimSpace(email)
	if email == "" || listID <= 0 {
		return
	}
	c.mu.Lock()
	c.hits[AuditHit{
		Email:  email,
		ListID: listID,
	}] = struct{}{}
	c.mu.Unlock()
}

func (c *AuditCounter) Drain() []AuditHit {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.hits) == 0 {
		return nil
	}
	out := make([]AuditHit, 0, len(c.hits))
	for hit := range c.hits {
		out = append(out, hit)
	}
	c.hits = make(map[AuditHit]struct{})
	return out
}
