// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2016 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package builtin

import (
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/snapcore/snapd/interfaces"
)

// LedInterface is the type of all the LED interfaces.
type LedInterface struct{}

// String returns the same value as Name().
func (iface *LedInterface) String() string {
	return iface.Name()
}

// Name returns the name of the LED interface.
func (iface *LedInterface) Name() string {
	return "led"
}

var ledAllowedPathPattern = regexp.MustCompile("^/sys/class/gpio/gpio[0-9]+/value$")

// SanitizeSlot checks and possibly modifies a slot.
// Valid "LED" slots must contain the attribute "path".
func (iface *LedInterface) SanitizeSlot(slot *interfaces.Slot) error {
	if iface.Name() != slot.Interface {
		panic(fmt.Sprintf("slot is not of interface %q", iface))
	}
	path, ok := slot.Attrs["path"].(string)
	if !ok || path == "" {
		return fmt.Errorf("led must contain the path attribute")
	}
	path = filepath.Clean(path)
	for _, pattern := range boolFileAllowedPathPatterns {
		if pattern.MatchString(path) {
			return nil
		}
	}
	return fmt.Errorf("led can only point at a value file")
}

// SanitizePlug checks and possibly modifies a plug.
func (iface *LedInterface) SanitizePlug(slot *interfaces.Plug) error {
	if iface.Name() != slot.Interface {
		panic(fmt.Sprintf("plug is not of interface %q", iface))
	}
	// NOTE: currently we don't check anything on the plug side.
	return nil
}

// ConnectedSlotSnippet returns security snippet specific to a given connection between the LED slot and some plug.
// Applications associated with the slot don't gain any extra permissions.
func (iface *LedInterface) ConnectedSlotSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor, interfaces.SecuritySecComp, interfaces.SecurityDBus, interfaces.SecurityUDev:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

// PermanentSlotSnippet returns security snippet permanently granted to LED slots.
// Applications associated with the slot, gain permission to export, unexport and set direction of any GPIO pin.
func (iface *LedInterface) PermanentSlotSnippet(slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	gpioSnippet := []byte(`
/sys/class/gpio/export rw,
/sys/class/gpio/unexport rw,
/sys/class/gpio/gpio[0-9]+/direction rw,
`)
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		// To provide GPIOs we need extra permissions to export/unexport and to
		// set the direction of each pin.
		if iface.isGPIO(slot) {
			return gpioSnippet, nil
		}
		return nil, nil
	case interfaces.SecuritySecComp, interfaces.SecurityDBus, interfaces.SecurityUDev:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

// ConnectedPlugSnippet returns security snippet specific to a given connection between the LED plug and some slot.
// Applications associated with the plug gain permission to read, write and lock the designated file.
func (iface *LedInterface) ConnectedPlugSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		// Allow write and lock on the file designated by the path.
		// Dereference symbolic links to file path handed out to apparmor since
		// sysfs is full of symlinks and apparmor requires uses real path for
		// filtering.
		path, err := iface.dereferencedPath(slot)
		if err != nil {
			return nil, fmt.Errorf("cannot compute plug security snippet: %v", err)
		}
		return []byte(fmt.Sprintf("%s rwk,\n", path)), nil
	case interfaces.SecuritySecComp, interfaces.SecurityDBus, interfaces.SecurityUDev:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

// PermanentPlugSnippet returns the configuration snippet required to use a LED interface.
// Applications associated with the plug don't gain any extra permissions.
func (iface *LedInterface) PermanentPlugSnippet(plug *interfaces.Plug, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor, interfaces.SecuritySecComp, interfaces.SecurityDBus, interfaces.SecurityUDev:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *LedInterface) dereferencedPath(slot *interfaces.Slot) (string, error) {
	if path, ok := slot.Attrs["path"].(string); ok {
		path, err := evalSymlinks(path)
		if err != nil {
			return "", err
		}
		return filepath.Clean(path), nil
	}
	panic("slot is not sanitized")
}

// isGPIO checks if a given slot refers to a GPIO pin.
func (iface *LedInterface) isGPIO(slot *interfaces.Slot) bool {
	if path, ok := slot.Attrs["path"].(string); ok {
		path = filepath.Clean(path)
		return ledAllowedPathPattern.MatchString(path)
	}
	panic("slot is not sanitized")
}

// AutoConnect returns true if plugs and slots should be implicitly
// auto-connected when an unambiguous connection candidate is available.
//
// This interface does not auto-connect.
func (iface *LedInterface) AutoConnect() bool {
	return false
}
