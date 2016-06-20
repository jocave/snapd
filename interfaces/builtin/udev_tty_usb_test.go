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

package builtin_test

import (
	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/builtin"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/testutil"
)

type UdevTtyUsbInterfaceSuite struct {
	testutil.BaseTest
	iface              interfaces.Interface
	ttyUsbAccessSlot   *interfaces.Slot
	badInterfaceSlot   *interfaces.Slot
	specificPlug       *interfaces.Plug
	badOnlyVendorPlug  *interfaces.Plug
	badOnlyProductPlug *interfaces.Plug
	badInterfacePlug   *interfaces.Plug
}

var _ = Suite(&UdevTtyUsbInterfaceSuite{
	iface: &builtin.UdevTtyUsbInterface{},
})

func (s *UdevTtyUsbInterfaceSuite) SetUpTest(c *C) {
	info, err := snap.InfoFromSnapYaml([]byte(`
name: ubuntu-core-snap
slots:
    tty-usb-access:
        interface: udev-tty-usb
    bad-interface: other-interface
plugs:
    specific-plug:
        interface: udev-tty-usb
        vendor-id: "1111"
        product-id: "2222"
    bad-only-vendor:
        interface: udev-tty-usb
        vendor-id: "1111"
    bad-only-product:
        interface: udev-tty-usb
        product-id: "2222"
    bad-interface: other-interface

apps:
    app-with-specific-plug:
        command: true
        plugs: [specific-plug]
    app2-with-specific-plug:
        command: true
        plugs: [specific-plug]
`))
	c.Assert(err, IsNil)
	s.ttyUsbAccessSlot = &interfaces.Slot{SlotInfo: info.Slots["tty-usb-access"]}
	s.badInterfaceSlot = &interfaces.Slot{SlotInfo: info.Slots["bad-interface"]}
	s.specificPlug = &interfaces.Plug{PlugInfo: info.Plugs["specific-plug"]}
	s.badOnlyVendorPlug = &interfaces.Plug{PlugInfo: info.Plugs["bad-only-vendor"]}
	s.badOnlyProductPlug = &interfaces.Plug{PlugInfo: info.Plugs["bad-only-product"]}
	s.badInterfacePlug = &interfaces.Plug{PlugInfo: info.Plugs["bad-interface"]}
}

func (s *UdevTtyUsbInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "udev-tty-usb")
}

func (s *UdevTtyUsbInterfaceSuite) TestSanitizeSpecificPlug(c *C) {
	err := s.iface.SanitizePlug(s.specificPlug)
	c.Assert(err, IsNil)
}

func (s *UdevTtyUsbInterfaceSuite) TestSanitizeBadOnlyVendorPlug(c *C) {
	err := s.iface.SanitizePlug(s.badOnlyVendorPlug)
	c.Assert(err, ErrorMatches, `Must have a product-id attribute`)
}

func (s *UdevTtyUsbInterfaceSuite) TestSanitizeBadOnlyProductPlug(c *C) {
	err := s.iface.SanitizePlug(s.badOnlyProductPlug)
	c.Assert(err, ErrorMatches, `Must have a vendor-id attribute`)
}

func (s *UdevTtyUsbInterfaceSuite) TestSanitizeBadInterfacePlug(c *C) {
	c.Assert(func() { s.iface.SanitizePlug(s.badInterfacePlug) }, PanicMatches,
		`plug is not of interface "udev-tty-usb"`)
}

func (s *UdevTtyUsbInterfaceSuite) TestPermanentSlotSnippetUnusedSecuritySystems(c *C) {
	// No extra apparmor permissions for slot
	snippet, err := s.iface.PermanentSlotSnippet(s.ttyUsbAccessSlot, interfaces.SecurityAppArmor)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra seccomp permissions for slot
	snippet, err = s.iface.PermanentSlotSnippet(s.ttyUsbAccessSlot, interfaces.SecuritySecComp)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra dbus permissions for slot
	snippet, err = s.iface.PermanentSlotSnippet(s.ttyUsbAccessSlot, interfaces.SecurityDBus)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// Other security types are not recognized
	snippet, err = s.iface.PermanentSlotSnippet(s.ttyUsbAccessSlot, "foo")
	c.Assert(err, ErrorMatches, `unknown security system`)
	c.Assert(snippet, IsNil)
}

func (s *UdevTtyUsbInterfaceSuite) TestConnectedSlotSnippetUnusedSecuritySystems(c *C) {
	// No extra apparmor permissions for slot
	snippet, err := s.iface.ConnectedSlotSnippet(s.specificPlug, s.ttyUsbAccessSlot, interfaces.SecurityAppArmor)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra seccomp permissions for slot
	snippet, err = s.iface.ConnectedSlotSnippet(s.specificPlug, s.ttyUsbAccessSlot, interfaces.SecuritySecComp)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra dbus permissions for slot
	snippet, err = s.iface.ConnectedSlotSnippet(s.specificPlug, s.ttyUsbAccessSlot, interfaces.SecurityDBus)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra udev permissions for slot
	snippet, err = s.iface.ConnectedSlotSnippet(s.specificPlug, s.ttyUsbAccessSlot, interfaces.SecurityUDev)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra mount permissions
	snippet, err = s.iface.ConnectedSlotSnippet(s.specificPlug, s.ttyUsbAccessSlot, interfaces.SecurityMount)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// Other security types are not recognized
	snippet, err = s.iface.ConnectedSlotSnippet(s.specificPlug, s.ttyUsbAccessSlot, "foo")
	c.Assert(err, ErrorMatches, `unknown security system`)
	c.Assert(snippet, IsNil)
}

func (s *UdevTtyUsbInterfaceSuite) TestPermanentPlugSnippetUnusedSecuritySystems(c *C) {
	// No extra apparmor permissions for plug
	snippet, err := s.iface.PermanentPlugSnippet(s.specificPlug, interfaces.SecurityAppArmor)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra seccomp permissions for plug
	snippet, err = s.iface.PermanentPlugSnippet(s.specificPlug, interfaces.SecuritySecComp)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra dbus permissions for plug
	snippet, err = s.iface.PermanentPlugSnippet(s.specificPlug, interfaces.SecurityDBus)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra udev permissions for plug
	snippet, err = s.iface.PermanentPlugSnippet(s.specificPlug, interfaces.SecurityUDev)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// no extra mount permissions
	snippet, err = s.iface.PermanentPlugSnippet(s.specificPlug, interfaces.SecurityMount)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// Other security types are not recognized
	snippet, err = s.iface.PermanentPlugSnippet(s.specificPlug, "foo")
	c.Assert(err, ErrorMatches, `unknown security system`)
	c.Assert(snippet, IsNil)
}

func (s *UdevTtyUsbInterfaceSuite) TestConnectedAppArmorSnippetForSpecificPlug(c *C) {
	expectedAppArmorSnippet := []byte("/dev/** rw,\n")

	snippet, err := s.iface.ConnectedPlugSnippet(s.specificPlug, s.ttyUsbAccessSlot, interfaces.SecurityAppArmor)
	c.Assert(err, IsNil)
	c.Assert(snippet, DeepEquals, expectedAppArmorSnippet, Commentf("\nexpected:\n%s\nfound:\n%s", expectedAppArmorSnippet, snippet))
}

func (s *UdevTtyUsbInterfaceSuite) TestConnectedUdevSnippetForSpecificPlug(c *C) {
	expectedUdevSnippet := []byte(`IMPORT{builtin}="usb_id"
SUBSYSTEM=="tty", SUBSYSTEMS=="usb", ATTRS{idProduct}=="1111", ATTRS{idVendor}=="2222", TAG+="snap_ubuntu-core-snap_app-with-specific-plug"
SUBSYSTEM=="tty", SUBSYSTEMS=="usb", ATTRS{idProduct}=="1111", ATTRS{idVendor}=="2222", TAG+="snap_ubuntu-core-snap_app2-with-specific-plug"
`)

	snippet, err := s.iface.ConnectedPlugSnippet(s.specificPlug, s.ttyUsbAccessSlot, interfaces.SecurityUDev)
	c.Assert(err, IsNil)
	c.Assert(snippet, DeepEquals, expectedUdevSnippet, Commentf("\nexpected:\n%s\nfound:\n%s", expectedUdevSnippet, snippet))
}

func (s *UdevTtyUsbInterfaceSuite) TestAutoConnect(c *C) {
	c.Check(s.iface.AutoConnect(), Equals, false)
}
