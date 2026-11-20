package statistic

import (
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
)

func newTestManager() *Manager {
	return &Manager{
		uploadTemp:    atomic.NewInt64(0),
		downloadTemp:  atomic.NewInt64(0),
		uploadBlip:    atomic.NewInt64(0),
		downloadBlip:  atomic.NewInt64(0),
		uploadTotal:   atomic.NewInt64(0),
		downloadTotal: atomic.NewInt64(0),
		failedTotal:   atomic.NewInt64(0),
		failedLimit:   DefaultFailedLimit,
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// P26: the speed counter parks after idleTicksToPark quiet ticks, the first
// byte wakes it and closes Resumed, a zero-size push does not wake it, and the
// speed is computed again after the wake.
func TestManagerParksWhenIdle(t *testing.T) {
	m := newTestManager()
	go m.handle(20 * time.Millisecond)

	if m.Resumed() != nil {
		t.Fatal("Resumed is not nil before the counter parked")
	}
	waitFor(t, "park", m.parked.Load)
	resumed := m.Resumed()
	if resumed == nil {
		t.Fatal("Resumed is nil while parked")
	}

	m.PushDownloaded(0) // EOF / read deadline
	m.PushUploaded(0)
	select {
	case <-resumed:
		t.Fatal("Resumed closed by a zero-size push")
	case <-time.After(50 * time.Millisecond):
	}

	m.PushDownloaded(1000)
	select {
	case <-resumed:
	case <-time.After(time.Second):
		t.Fatal("Resumed not closed after traffic")
	}
	if m.parked.Load() {
		t.Fatal("still parked after traffic")
	}
	sawSpeed := false
	waitFor(t, "speed after wake, then park", func() bool {
		if _, down := m.Now(); down == 1000 {
			sawSpeed = true
		}
		return m.parked.Load()
	})
	if !sawSpeed {
		t.Fatal("the 1000 bytes never showed up as speed")
	}
	if up, down := m.Now(); up != 0 || down != 0 {
		t.Fatalf("speed while parked = %d/%d, want 0/0", up, down)
	}
	if _, down := m.Total(); down != 1000 {
		t.Fatalf("download total = %d, want 1000", down)
	}
}

// Bytes counted in the window between the last tick and parking must not be
// stranded: park sees them and does not sleep.
func TestManagerParkSeesLateBytes(t *testing.T) {
	m := newTestManager()
	m.uploadTemp.Add(5) // as if a Push ran just before parked was set
	done := make(chan struct{})
	go func() { m.park(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("park slept with bytes pending")
	}
	if m.parked.Load() {
		t.Fatal("parked with bytes pending")
	}
}

// Concurrent pushes while parking never lose a wake-up.
func TestManagerParkRace(t *testing.T) {
	for i := 0; i < 200; i++ {
		m := newTestManager()
		done := make(chan struct{})
		go func() { m.park(); close(done) }()
		go m.PushUploaded(1)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("round %d: lost wake-up", i)
		}
	}
}

func BenchmarkManagerPushAwake(b *testing.B) {
	m := newTestManager()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.PushDownloaded(1500)
		}
	})
}
