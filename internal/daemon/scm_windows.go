package daemon

import (
	"errors"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var _ ServiceManager = SCM{}

// SCM is the real Windows Service Control Manager. Every operation opens
// the manager and the service with only the access it needs, so a query
// works without elevation: status run by an unelevated administrator or
// an interactive user, whom the default service ACL lets read the
// configuration and the state, still sees the installed service.
type SCM struct{}

// Service access of each operation. The manager is opened with
// SC_MANAGER_CONNECT, plus SC_MANAGER_CREATE_SERVICE for Create.
const (
	queryAccess    = windows.SERVICE_QUERY_CONFIG | windows.SERVICE_QUERY_STATUS
	updateAccess   = windows.SERVICE_QUERY_CONFIG | windows.SERVICE_CHANGE_CONFIG
	recoveryAccess = windows.SERVICE_CHANGE_CONFIG | windows.SERVICE_START // a restart action needs SERVICE_START
	startAccess    = windows.SERVICE_START
	stopAccess     = windows.SERVICE_STOP | windows.SERVICE_QUERY_STATUS
	deleteAccess   = windows.DELETE
)

// open connects to the SCM (SC_MANAGER_CONNECT) and opens the service
// with access.
func (SCM) open(name string, access uint32) (*mgr.Mgr, *mgr.Service, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, nil, err
	}
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, nil, err
	}
	m := &mgr.Mgr{Handle: h}
	sh, err := windows.OpenService(h, n, access)
	if err != nil {
		m.Disconnect()
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil, nil, ErrServiceNotInstalled
		}
		return nil, nil, err
	}
	return m, &mgr.Service{Name: name, Handle: sh}, nil
}

// with runs f on the service opened with access.
func (c SCM) with(name string, access uint32, f func(s *mgr.Service) error) error {
	m, s, err := c.open(name, access)
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
	err := c.with(name, queryAccess, func(s *mgr.Service) error {
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
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_CREATE_SERVICE)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(h)
	ptr := func(s string) *uint16 {
		p, _ := windows.UTF16PtrFromString(s)
		return p
	}
	start := uint32(windows.SERVICE_DEMAND_START)
	if c.AutoStart {
		start = windows.SERVICE_AUTO_START
	}
	// The new service's handle is only closed: it needs no access.
	s, err := windows.CreateService(h, ptr(name), ptr(c.DisplayName), windows.SERVICE_QUERY_STATUS,
		windows.SERVICE_WIN32_OWN_PROCESS, start, windows.SERVICE_ERROR_NORMAL, ptr(c.Command),
		nil, nil, nil, ptr(c.Account), nil)
	if err != nil {
		return err
	}
	return windows.CloseServiceHandle(s)
}

// Update implements ServiceManager.
func (c SCM) Update(name string, sc ServiceConfig) error {
	return c.with(name, updateAccess, func(s *mgr.Service) error {
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
	return c.with(name, recoveryAccess, func(s *mgr.Service) error {
		restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: r.RestartDelay}
		if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, uint32(r.ResetPeriod/time.Second)); err != nil {
			return err
		}
		return s.SetRecoveryActionsOnNonCrashFailures(true)
	})
}

// Start implements ServiceManager. A running service is not an error.
func (c SCM) Start(name string) error {
	return c.with(name, startAccess, func(s *mgr.Service) error {
		if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return err
		}
		return nil
	})
}

// Stop implements ServiceManager. A service that is still starting
// accepts no control: Stop waits (at most stopWait) for the start to
// finish, then stops it.
func (c SCM) Stop(name string) error {
	return c.with(name, stopAccess, func(s *mgr.Service) error {
		return stopService(scmService{s}, name, stopWait, stopPoll, time.Sleep)
	})
}

// scmService is an open service as a serviceControl.
type scmService struct{ s *mgr.Service }

func (c scmService) queryState() (ServiceState, error) {
	st, err := c.s.Query()
	if err != nil {
		return 0, err
	}
	return serviceState(st.State), nil
}

func (c scmService) sendStop() error {
	_, err := c.s.Control(svc.Stop)
	switch {
	case errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE):
		return errServiceNotActive
	case errors.Is(err, windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL):
		return errCannotAcceptStop
	}
	return err
}

// Delete implements ServiceManager. A service already marked for deletion
// is not an error.
func (c SCM) Delete(name string) error {
	return c.with(name, deleteAccess, func(s *mgr.Service) error {
		if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			return err
		}
		return nil
	})
}
