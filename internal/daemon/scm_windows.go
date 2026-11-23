package daemon

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// stopWait bounds how long SCM.Stop waits for the service to stop.
const stopWait = 30 * time.Second

var _ ServiceManager = SCM{}

// SCM is the real Windows Service Control Manager.
type SCM struct{}

// open connects to the SCM and opens the service.
func (SCM) open(name string) (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, err
	}
	s, err := m.OpenService(name)
	if err != nil {
		m.Disconnect()
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil, nil, ErrServiceNotInstalled
		}
		return nil, nil, err
	}
	return m, s, nil
}

// with runs f on the open service.
func (c SCM) with(name string, f func(s *mgr.Service) error) error {
	m, s, err := c.open(name)
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	return f(s)
}

// Query implements ServiceManager.
func (c SCM) Query(name string) (ServiceInfo, error) {
	var info ServiceInfo
	err := c.with(name, func(s *mgr.Service) error {
		st, err := s.Query()
		if err != nil {
			return err
		}
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		info = ServiceInfo{State: serviceState(st.State), Command: cfg.BinaryPathName}
		return nil
	})
	return info, err
}

func serviceState(s svc.State) ServiceState {
	switch s {
	case svc.Stopped:
		return ServiceStopped
	case svc.StartPending:
		return ServiceStartPending
	case svc.StopPending:
		return ServiceStopPending
	}
	return ServiceRunning
}

// Create implements ServiceManager. It calls CreateService itself, so the
// binary path name is exactly c.Command.
func (SCM) Create(name string, c ServiceConfig) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	ptr := func(s string) *uint16 {
		p, _ := windows.UTF16PtrFromString(s)
		return p
	}
	start := uint32(windows.SERVICE_DEMAND_START)
	if c.AutoStart {
		start = windows.SERVICE_AUTO_START
	}
	h, err := windows.CreateService(m.Handle, ptr(name), ptr(c.DisplayName), windows.SERVICE_ALL_ACCESS,
		windows.SERVICE_WIN32_OWN_PROCESS, start, windows.SERVICE_ERROR_NORMAL, ptr(c.Command),
		nil, nil, nil, ptr(c.Account), nil)
	if err != nil {
		return err
	}
	return windows.CloseServiceHandle(h)
}

// Update implements ServiceManager.
func (c SCM) Update(name string, sc ServiceConfig) error {
	return c.with(name, func(s *mgr.Service) error {
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		cfg.ServiceType = windows.SERVICE_WIN32_OWN_PROCESS
		cfg.BinaryPathName = sc.Command
		cfg.DisplayName = sc.DisplayName
		cfg.ServiceStartName = sc.Account
		cfg.StartType = mgr.StartManual
		if sc.AutoStart {
			cfg.StartType = mgr.StartAutomatic
		}
		cfg.DelayedAutoStart = false
		return s.UpdateConfig(cfg)
	})
}

// SetRecovery implements ServiceManager: three restarts, so every later
// failure restarts too, also when serve exits with an error.
func (c SCM) SetRecovery(name string, r Recovery) error {
	return c.with(name, func(s *mgr.Service) error {
		restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: r.RestartDelay}
		if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, uint32(r.ResetPeriod/time.Second)); err != nil {
			return err
		}
		return s.SetRecoveryActionsOnNonCrashFailures(true)
	})
}

// Start implements ServiceManager. A running service is not an error.
func (c SCM) Start(name string) error {
	return c.with(name, func(s *mgr.Service) error {
		if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return err
		}
		return nil
	})
}

// Stop implements ServiceManager.
func (c SCM) Stop(name string) error {
	return c.with(name, func(s *mgr.Service) error {
		st, err := s.Control(svc.Stop)
		if errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return nil
		}
		if err != nil {
			return err
		}
		for deadline := time.Now().Add(stopWait); st.State != svc.Stopped; {
			if time.Now().After(deadline) {
				return fmt.Errorf("the %s service did not stop within %s", name, stopWait)
			}
			time.Sleep(250 * time.Millisecond)
			if st, err = s.Query(); err != nil {
				return err
			}
		}
		return nil
	})
}

// Delete implements ServiceManager. A service already marked for deletion
// is not an error.
func (c SCM) Delete(name string) error {
	return c.with(name, func(s *mgr.Service) error {
		if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			return err
		}
		return nil
	})
}
