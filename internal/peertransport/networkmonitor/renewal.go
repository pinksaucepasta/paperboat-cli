package networkmonitor

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"

	//paperboat:allow-source-policy tailscale-import owner=peer-networking reason=selected-portmapper-contract
	"tailscale.com/net/portmapper/portmappertype"
	//paperboat:allow-source-policy tailscale-import owner=peer-networking reason=selected-netmon-event-bus
	"tailscale.com/util/eventbus"
)

type leaseRenewal struct {
	client     *eventbus.Client
	subscriber *eventbus.Subscriber[portmappertype.Mapping]
	stop       chan struct{}
	wait       sync.WaitGroup
	trigger    func() bool
	mu         sync.Mutex
	protocol   string
}

func newLeaseRenewal(bus *eventbus.Bus, trigger func() bool) *leaseRenewal {
	client := bus.Client("paperboat-port-mapping-renewal")
	renewal := &leaseRenewal{
		client: client, subscriber: eventbus.Subscribe[portmappertype.Mapping](client),
		stop: make(chan struct{}), trigger: trigger,
	}
	renewal.wait.Add(1)
	go renewal.run()
	return renewal
}

func (r *leaseRenewal) run() {
	defer r.wait.Done()
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	var timerC <-chan time.Time
	var goodUntil time.Time
	for {
		select {
		case mapping := <-r.subscriber.Events():
			r.mu.Lock()
			r.protocol = mappingProtocol(mapping.Type)
			r.mu.Unlock()
			delay, ok := mappingRenewalDelay(time.Now(), mapping.GoodUntil, renewalRandom())
			if !ok {
				continue
			}
			goodUntil = mapping.GoodUntil
			resetTimer(timer, delay)
			timerC = timer.C
		case <-timerC:
			timerC = nil
			if r.trigger != nil {
				r.trigger()
			}
			remaining := time.Until(goodUntil)
			if remaining > 0 {
				retry := min(max(remaining/4, time.Second), 30*time.Second)
				resetTimer(timer, retry)
				timerC = timer.C
			}
		case <-r.stop:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		}
	}
}

func (r *leaseRenewal) Protocol() string {
	if r == nil {
		return "unknown"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.protocol == "" {
		return "unknown"
	}
	return r.protocol
}

func mappingProtocol(value string) string {
	switch value {
	case "pcp":
		return "pcp"
	case "pmp":
		return "nat_pmp"
	case "upnp":
		return "upnp"
	default:
		return "unknown"
	}
}

func (r *leaseRenewal) Close() {
	if r == nil {
		return
	}
	select {
	case <-r.stop:
		return
	default:
		close(r.stop)
	}
	r.client.Close()
	r.wait.Wait()
}

func mappingRenewalDelay(now, goodUntil time.Time, random uint64) (time.Duration, bool) {
	remaining := goodUntil.Sub(now)
	if now.IsZero() || goodUntil.IsZero() || remaining <= 0 {
		return 0, false
	}
	fraction := 0.55 + 0.10*(float64(random)/float64(^uint64(0)))
	delay := time.Duration(float64(remaining) * fraction)
	if delay <= 0 || delay >= remaining {
		return 0, false
	}
	return delay, true
}

func renewalRandom() uint64 {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return ^uint64(0) / 2
	}
	return binary.BigEndian.Uint64(value[:])
}

func resetTimer(timer *time.Timer, delay time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(delay)
}
