package menubar

import (
	"errors"
	"fmt"
	"io/fs"

	"golang.org/x/sys/windows/registry"
)

// RegistryRunKey is a key under HKEY_CURRENT_USER, such as the user's Run
// key (UserRunKey).
type RegistryRunKey struct{ Path string }

var _ RunKey = RegistryRunKey{}

// UserRunKey is HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run.
func UserRunKey() RegistryRunKey { return RegistryRunKey{Path: RunKeyPath} }

func notExist(name string, err error) error {
	if errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("registry value %s: %w", name, fs.ErrNotExist)
	}
	return err
}

// Get returns the string value name. A value of another type is an error
// that does not wrap fs.ErrNotExist, so it is replaced when it should hold
// the tray's path.
func (k RegistryRunKey) Get(name string) (string, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, k.Path, registry.QUERY_VALUE)
	if err != nil {
		return "", notExist(name, err)
	}
	defer key.Close()
	v, typ, err := key.GetStringValue(name)
	if err != nil {
		return "", notExist(name, err)
	}
	if typ != registry.SZ {
		return "", fmt.Errorf("registry value %s has type %d, not a string", name, typ)
	}
	return v, nil
}

// Set writes value as the string value name, creating the key if needed.
func (k RegistryRunKey) Set(name, value string) error {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, k.Path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.SetStringValue(name, value)
}

// Delete removes the value name.
func (k RegistryRunKey) Delete(name string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, k.Path, registry.SET_VALUE)
	if err != nil {
		return notExist(name, err)
	}
	defer key.Close()
	return notExist(name, key.DeleteValue(name))
}
