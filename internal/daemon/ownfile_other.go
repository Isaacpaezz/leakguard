//go:build !windows

package daemon

// ownByAdministrators does nothing: only Windows gives the service's copy
// to Administrators.
func ownByAdministrators(string) error { return nil }
