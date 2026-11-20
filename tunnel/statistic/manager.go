package statistic

import (
	"os"
	"sync"
	stdatomic "sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/memory"
)

var DefaultManager *Manager

func init() {
	DefaultManager = &Manager{
		uploadTemp:    atomic.NewInt64(0),
		downloadTemp:  atomic.NewInt64(0),
		uploadBlip:    atomic.NewInt64(0),
		downloadBlip:  atomic.NewInt64(0),
		uploadTotal:   atomic.NewInt64(0),
		downloadTotal: atomic.NewInt64(0),
		failedTotal:   atomic.NewInt64(0),
		failedLimit:   DefaultFailedLimit,
		pid:           int32(os.Getpid()),
	}

	go DefaultManager.handle(time.Second)
}

// idleTicksToPark is how many ticks without a byte either way put the speed
// counter to sleep (P26).
const idleTicksToPark = 5

type Manager struct {
	connections   xsync.Map[string, Tracker]
	uploadTemp    atomic.Int64
	downloadTemp  atomic.Int64
	uploadBlip    atomic.Int64
	downloadBlip  atomic.Int64
	uploadTotal   atomic.Int64
	downloadTotal atomic.Int64
	failedTotal   atomic.Int64
	failedMu      sync.Mutex
	failedRing    []*FailedConnection
	failedHead    int
	failedCount   int
	failedLimit   int
	pid           int32
	memory        uint64

	// P26: the speed ticker sleeps while no traffic moves. parked is read on
	// every Push*; parkMu orders park/unpark and guards resumed.
	parked  stdatomic.Bool
	parkMu  sync.Mutex
	resumed chan struct{} // closed when traffic resumes after a park
}

func (m *Manager) Join(c Tracker) {
	m.connections.Store(c.ID(), c)
}

func (m *Manager) Leave(c Tracker) {
	m.connections.Delete(c.ID())
}

func (m *Manager) Get(id string) (c Tracker) {
	if value, ok := m.connections.Load(id); ok {
		c = value
	}
	return
}

func (m *Manager) Range(f func(c Tracker) bool) {
	m.connections.Range(func(key string, value Tracker) bool {
		return f(value)
	})
}

// CloseByUser closes every tracked connection of one inbound user and returns
// how many it closed. VLESS users do not need it: revoking a user closes the
// client connections and trackers bound to its record (C.InboundSession).
func (m *Manager) CloseByUser(inbound, user string) int {
	var matched []Tracker
	m.connections.Range(func(_ string, c Tracker) bool {
		metadata := c.Info().Metadata
		if metadata != nil && metadata.InName == inbound && metadata.InUser == user {
			matched = append(matched, c)
		}
		return true
	})
	for _, c := range matched {
		_ = c.Close()
	}
	return len(matched)
}

func (m *Manager) PushUploaded(size int64) {
	m.uploadTemp.Add(size)
	m.uploadTotal.Add(size)
	if size > 0 && m.parked.Load() { // EOF and deadline reads push 0
		m.unpark()
	}
}

func (m *Manager) PushDownloaded(size int64) {
	m.downloadTemp.Add(size)
	m.downloadTotal.Add(size)
	if size > 0 && m.parked.Load() { // EOF and deadline reads push 0
		m.unpark()
	}
}

// Resumed returns a channel that is closed when traffic moves again, or nil
// while the speed counter is running. A periodic consumer of the counters
// (the app's own statistics loop) can sleep on it instead of ticking through
// idle time: if ch := Resumed(); ch != nil { <-ch }.
func (m *Manager) Resumed() <-chan struct{} {
	m.parkMu.Lock()
	defer m.parkMu.Unlock()
	if !m.parked.Load() {
		return nil
	}
	return m.resumed
}

func (m *Manager) Now() (up int64, down int64) {
	return m.uploadBlip.Load(), m.downloadBlip.Load()
}

func (m *Manager) Total() (up, down int64) {
	return m.uploadTotal.Load(), m.downloadTotal.Load()
}

func (m *Manager) Memory() uint64 {
	m.updateMemory()
	return m.memory
}

func (m *Manager) Snapshot() *Snapshot {
	var connections []*TrackerInfo
	m.Range(func(c Tracker) bool {
		connections = append(connections, c.Info())
		return true
	})
	return &Snapshot{
		UploadTotal:       m.uploadTotal.Load(),
		DownloadTotal:     m.downloadTotal.Load(),
		Connections:       connections,
		Memory:            m.memory,
		FailedTotal:       m.failedTotal.Load(),
		FailedConnections: m.FailedConnections(0),
	}
}

func (m *Manager) updateMemory() {
	stat, err := memory.GetMemoryInfo(m.pid)
	if err != nil {
		return
	}
	m.memory = stat.RSS
}

func (m *Manager) ResetStatistic() {
	m.uploadTemp.Store(0)
	m.uploadBlip.Store(0)
	m.uploadTotal.Store(0)
	m.downloadTemp.Store(0)
	m.downloadBlip.Store(0)
	m.downloadTotal.Store(0)
	m.failedTotal.Store(0)
	m.ClearFailed()
}

// handle turns the byte counts of every interval into the current speed
// (Now). After idleTicksToPark intervals without traffic it stops the ticker
// and waits for the next Push*: a ticker that fires every second forever keeps
// a phone's CPU and the Go scheduler from sleeping (P26). The speed reads
// 0 while parked, which is what it is.
func (m *Manager) handle(interval time.Duration) {
	ticker := time.NewTicker(interval)
	idle := 0
	for range ticker.C {
		up, down := m.uploadTemp.Swap(0), m.downloadTemp.Swap(0)
		m.uploadBlip.Store(up)
		m.downloadBlip.Store(down)
		if up != 0 || down != 0 {
			idle = 0
			continue
		}
		if idle++; idle < idleTicksToPark {
			continue
		}
		ticker.Stop()
		m.park()
		idle = 0
		ticker.Reset(interval)
	}
}

// park blocks until traffic moves.
func (m *Manager) park() {
	m.parkMu.Lock()
	resumed := make(chan struct{})
	m.resumed = resumed
	m.parked.Store(true)
	m.parkMu.Unlock()
	// A Push that read parked before the Store above counted its bytes before
	// that too, so they show up here; a later Push sees parked and wakes us.
	if m.uploadTemp.Load() != 0 || m.downloadTemp.Load() != 0 {
		m.unpark()
	}
	<-resumed
}

func (m *Manager) unpark() {
	m.parkMu.Lock()
	if m.parked.Load() {
		m.parked.Store(false)
		close(m.resumed)
	}
	m.parkMu.Unlock()
}

type Snapshot struct {
	DownloadTotal     int64               `json:"downloadTotal"`
	UploadTotal       int64               `json:"uploadTotal"`
	Connections       []*TrackerInfo      `json:"connections"`
	Memory            uint64              `json:"memory"`
	FailedTotal       int64               `json:"failedTotal,omitempty"`
	FailedConnections []*FailedConnection `json:"failedConnections,omitempty"`
}
