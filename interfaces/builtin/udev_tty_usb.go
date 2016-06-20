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
	"bytes"
	"fmt"

	"github.com/snapcore/snapd/interfaces"
)

// UdevTtyUsbInterface is the type for serial port interfaces.
type UdevTtyUsbInterface struct{}

// Name of the  interface.
func (iface *UdevTtyUsbInterface) Name() string {
	return "udev-tty-usb"
}

func (iface *UdevTtyUsbInterface) String() string {
	return iface.Name()
}

var udevHeader = `IMPORT{builtin}="usb_id"`
var udevEntryPattern = `SUBSYSTEM=="tty", SUBSYSTEMS=="usb", ATTRS{idProduct}=="%s", ATTRS{idVendor}=="%s"`
var udevEntryTagPattern = `, TAG+="%s"`

// SanitizeSlot checks slot validity
func (iface *UdevTtyUsbInterface) SanitizeSlot(slot *interfaces.Slot) error {
	// check slot name
	if iface.Name() != slot.Interface {
		panic(fmt.Sprintf("slot is not of interface %q", iface))
	}
	return nil
}

// PermanentSlotSnippet - no permissions given to slot permanently
func (iface *UdevTtyUsbInterface) PermanentSlotSnippet(slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor, interfaces.SecuritySecComp, interfaces.SecurityDBus, interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

// ConnectedSlotSnippet - no permissions given to slot on connection
func (iface *UdevTtyUsbInterface) ConnectedSlotSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor, interfaces.SecurityDBus, interfaces.SecuritySecComp, interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

// SanitizePlug checks plug validity
func (iface *UdevTtyUsbInterface) SanitizePlug(plug *interfaces.Plug) error {
	if iface.Name() != plug.Interface {
		panic(fmt.Sprintf("plug is not of interface %q", iface))
	}

	// only accept if we have both vendor-id and product-id attributes
	idVendor, vOk := plug.Attrs["vendor-id"].(string)
	if !vOk || idVendor == "" {
		return fmt.Errorf("Must have a vendor-id attribute")
	}

	idProduct, pOk := plug.Attrs["product-id"].(string)
	if !pOk || idProduct == "" {
		return fmt.Errorf("Must have a product-id attribute")
	}

	return nil
}

// PermanentPlugSnippet no permissions provided to plug permanently
func (iface *UdevTtyUsbInterface) PermanentPlugSnippet(plug *interfaces.Plug, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor, interfaces.SecuritySecComp, interfaces.SecurityDBus, interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

// ConnectedPlugSnippet returns security snippet specific to the plug
func (iface *UdevTtyUsbInterface) ConnectedPlugSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		return []byte("/dev/** rw,\n"), nil
	case interfaces.SecurityUDev:
		idVendor, vOk := plug.Attrs["vendor-id"].(string)
		idProduct, pOk := plug.Attrs["product-id"].(string)
		if !vOk || !pOk {
			return nil, fmt.Errorf("Failed to get plug attributes")
		}
		var udevSnippet bytes.Buffer
		udevSnippet.WriteString(udevHeader)
		udevSnippet.WriteString("\n")
		for appName := range plug.Apps {
			udevSnippet.WriteString(fmt.Sprintf(udevEntryPattern, idVendor, idProduct))
			tag := fmt.Sprintf("snap_%s_%s", plug.Snap.Name(), appName)
			udevSnippet.WriteString(fmt.Sprintf(udevEntryTagPattern, tag))
			udevSnippet.WriteString("\n")
		}
		return udevSnippet.Bytes(), nil
	case interfaces.SecuritySecComp, interfaces.SecurityDBus, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

// AutoConnect indicates whether this type of interface should allow autoconnect
func (iface *UdevTtyUsbInterface) AutoConnect() bool {
	return false
}
