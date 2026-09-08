package service

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type publicMailKind string

const (
	publicMailMagicLink     publicMailKind = "magic_link"
	publicMailPasswordReset publicMailKind = "password_reset"
)

type publicMailJob struct {
	kind     publicMailKind
	identity string
}

type publicMailLog struct {
	kind  publicMailKind
	class string
}

type publicMailQueue struct {
	mu         sync.RWMutex
	accepting  bool
	jobs       chan publicMailJob
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	shutdown   sync.Once
	workers    sync.WaitGroup
	jobTimeout time.Duration
	log        *slog.Logger
	logEvents  chan publicMailLog
	logDone    chan struct{}
	process    func(context.Context, publicMailJob)
}

func newPublicMailQueue(workerCount, capacity int, jobTimeout time.Duration, log *slog.Logger, process func(context.Context, publicMailJob)) (*publicMailQueue, error) {
	if workerCount <= 0 {
		return nil, fmt.Errorf("public mail workers must be positive")
	}
	if capacity <= 0 {
		return nil, fmt.Errorf("public mail queue capacity must be positive")
	}
	if jobTimeout <= 0 {
		return nil, fmt.Errorf("public mail job timeout must be positive")
	}
	if process == nil {
		return nil, fmt.Errorf("public mail processor is required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	q := &publicMailQueue{
		accepting: true, jobs: make(chan publicMailJob, capacity), ctx: ctx, cancel: cancel,
		done: make(chan struct{}), jobTimeout: jobTimeout, log: log,
		logEvents: make(chan publicMailLog, 16), logDone: make(chan struct{}), process: process,
	}
	go q.logWorker()
	q.workers.Add(workerCount)
	for range workerCount {
		go q.worker()
	}
	go func() {
		q.workers.Wait()
		q.cancel()
		<-q.logDone
		close(q.done)
	}()
	return q, nil
}

func (q *publicMailQueue) enqueue(job publicMailJob) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if !q.accepting {
		q.logClass(job.kind, "queue_closed")
		return
	}
	select {
	case q.jobs <- job:
	default:
		q.logClass(job.kind, "queue_full")
	}
}

func (q *publicMailQueue) worker() {
	defer q.workers.Done()
	for {
		select {
		case <-q.ctx.Done():
			return
		case job, ok := <-q.jobs:
			if !ok {
				return
			}
			q.run(job)
		}
	}
}

func (q *publicMailQueue) run(job publicMailJob) {
	ctx, cancel := context.WithTimeout(q.ctx, q.jobTimeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			q.logClass(job.kind, "worker_panic")
		}
	}()
	q.process(ctx, job)
}

func (q *publicMailQueue) logClass(kind publicMailKind, class string) {
	if q.log == nil {
		return
	}
	select {
	case q.logEvents <- publicMailLog{kind: kind, class: class}:
	default:
	}
}

func (q *publicMailQueue) logWorker() {
	defer close(q.logDone)
	for {
		select {
		case <-q.ctx.Done():
			return
		case event := <-q.logEvents:
			q.log.Warn("public mail suppressed", "kind", string(event.kind), "class", event.class)
		}
	}
}

func (q *publicMailQueue) Shutdown(ctx context.Context) error {
	q.shutdown.Do(func() {
		q.mu.Lock()
		q.accepting = false
		close(q.jobs)
		q.mu.Unlock()
	})
	select {
	case <-q.done:
		return nil
	case <-ctx.Done():
		q.cancel()
		return ctx.Err()
	}
}

func (a *Auth) processPublicMail(ctx context.Context, job publicMailJob) {
	switch job.kind {
	case publicMailMagicLink:
		a.processMagicLink(ctx, job.identity)
	case publicMailPasswordReset:
		a.processPasswordReset(ctx, job.identity)
	}
}
