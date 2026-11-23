package daemon

import (
	"errors"
	"fmt"
	"time"
)

const (
	// stopWait bounds how long SCM.Stop waits for the service to finish
	// starting and then to stop.
	stopWait = 30 * time.Second
	// stopPoll is how often SCM.Stop asks the service's state.
	stopPoll = 250 * time.Millisecond
)

// What the Service Control Manager answers to the stop control.
var (
	// errServiceNotActive: the service is not running.
	errServiceNotActive = errors.New("the service is not running")
	// errCannotAcceptStop: the service cannot take controls now, e.g.
	// while it is still starting.
	errCannotAcceptStop = errors.New("the service cannot accept the stop control now")
)

// serviceControl is one open Windows service, for stopService.
type serviceControl interface {
	queryState() (ServiceState, error)
	// sendStop sends the stop control and returns at once.
	sendStop() error
}

// stopService stops the service and returns once it has stopped. A
// service that is still starting accepts no control, so it first waits
// for the start to finish; a service that refuses the control for a
// moment gets it again. Everything is bounded by wait, polled every poll.
func stopService(c serviceControl, name string, wait, poll time.Duration, sleep func(time.Duration)) error {
	sent := false
	for waited := time.Duration(0); ; waited += poll {
		st, err := c.queryState()
		if err != nil {
			return err
		}
		switch st {
		case ServiceStopped:
			return nil
		case ServiceStartPending, ServiceStopPending:
			// Wait for the start or the stop to finish.
		default:
			if !sent {
				switch err := c.sendStop(); {
				case errors.Is(err, errServiceNotActive):
					return nil
				case errors.Is(err, errCannotAcceptStop):
					// Busy for a moment: ask again on the next poll.
				case err != nil:
					return err
				default:
					sent = true
				}
			}
		}
		if waited >= wait {
			if st == ServiceStartPending {
				return fmt.Errorf("the %s service did not finish starting within %s, so it could not be stopped", name, wait)
			}
			return fmt.Errorf("the %s service did not stop within %s", name, wait)
		}
		sleep(poll)
	}
}
