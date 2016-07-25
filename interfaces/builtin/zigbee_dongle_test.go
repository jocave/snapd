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

type ZigbeeDongleInterfaceSuite struct {
	testutil.BaseTest
	iface              interfaces.Interface
	zigbeeAccessSlot   *interfaces.Slot
	badInterfaceSlot   *interfaces.Slot
	genericPlug        *interfaces.Plug
	specificPlug       *interfaces.Plug
	badOnlyVendorPlug  *interfaces.Plug
	badOnlyProductPlug *interfaces.Plug
	badInterfacePlug   *interfaces.Plug
}

var _ = Suite(&ZigbeeDongleInterfaceSuite{
	iface: &builtin.ZigbeeDongleInterface{},
})

func (s *ZigbeeDongleInterfaceSuite) SetUpTest(c *C) {
	info, err := snap.InfoFromSnapYaml([]byte(`
name: ubuntu-core-snap
slots:
    zigbee-access:
        interface: zigbee-dongle
    bad-interface: other-interface
plugs:
    generic-plug: zigbee-dongle
    specific-plug:
        interface: zigbee-dongle
        id-vendor: "1111"
        id-product: "2222"
    bad-only-vendor:
        interface: zigbee-dongle
        id-vendor: "1111"
    bad-only-product:
        interface: zigbee-dongle
        id-product: "2222"
    bad-interface: other-interface

apps:
    app-with-generic-plug:
        command: true
        plugs: [generic-plug]
    app-with-specific-plug:
        command: true
        plugs: [specific-plug]
    app2-with-specific-plug:
        command: true
        plugs: [specific-plug]
`))
	c.Assert(err, IsNil)
	s.zigbeeAccessSlot = &interfaces.Slot{SlotInfo: info.Slots["zigbee-access"]}
	s.badInterfaceSlot = &interfaces.Slot{SlotInfo: info.Slots["bad-interface"]}
	s.genericPlug = &interfaces.Plug{PlugInfo: info.Plugs["generic-plug"]}
	s.specificPlug = &interfaces.Plug{PlugInfo: info.Plugs["specific-plug"]}
	s.badOnlyVendorPlug = &interfaces.Plug{PlugInfo: info.Plugs["bad-only-vendor"]}
	s.badOnlyProductPlug = &interfaces.Plug{PlugInfo: info.Plugs["bad-only-product"]}
	s.badInterfacePlug = &interfaces.Plug{PlugInfo: info.Plugs["bad-interface"]}
}

func (s *ZigbeeDongleInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "zigbee-dongle")
}

func (s *ZigbeeDongleInterfaceSuite) TestSanitizeGenericPlug(c *C) {
	err := s.iface.SanitizePlug(s.genericPlug)
	c.Assert(err, IsNil)
}

func (s *ZigbeeDongleInterfaceSuite) TestSanitizeSpecificPlug(c *C) {
	err := s.iface.SanitizePlug(s.specificPlug)
	c.Assert(err, IsNil)
}

func (s *ZigbeeDongleInterfaceSuite) TestSanitizeBadOnlyVendorPlug(c *C) {
	err := s.iface.SanitizePlug(s.badOnlyVendorPlug)
	c.Assert(err, ErrorMatches, `id-vendor without id-product`)
}

func (s *ZigbeeDongleInterfaceSuite) TestSanitizeBadOnlyProductPlug(c *C) {
	err := s.iface.SanitizePlug(s.badOnlyProductPlug)
	c.Assert(err, ErrorMatches, `id-product without id-vendor`)
}

func (s *ZigbeeDongleInterfaceSuite) TestSanitizeBadInterfacePlug(c *C) {
	c.Assert(func() { s.iface.SanitizePlug(s.badInterfacePlug) }, PanicMatches,
		`plug is not of interface "zigbee-dongle"`)
}

func (s *ZigbeeDongleInterfaceSuite) TestPermanentSlotSnippetUnusedSecuritySystems(c *C) {
	// No extra apparmor permissions for slot
	snippet, err := s.iface.PermanentSlotSnippet(s.zigbeeAccessSlot, interfaces.SecurityAppArmor)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra seccomp permissions for slot
	snippet, err = s.iface.PermanentSlotSnippet(s.zigbeeAccessSlot, interfaces.SecuritySecComp)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra dbus permissions for slot
	snippet, err = s.iface.PermanentSlotSnippet(s.zigbeeAccessSlot, interfaces.SecurityDBus)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// Other security types are not recognized
	snippet, err = s.iface.PermanentSlotSnippet(s.zigbeeAccessSlot, "foo")
	c.Assert(err, ErrorMatches, `unknown security system`)
	c.Assert(snippet, IsNil)
}

func (s *ZigbeeDongleInterfaceSuite) TestConnectedSlotSnippetUnusedSecuritySystems(c *C) {
	for _, plug := range []*interfaces.Plug{s.genericPlug, s.specificPlug} {
		// No extra apparmor permissions for slot
		snippet, err := s.iface.ConnectedSlotSnippet(plug, s.zigbeeAccessSlot, interfaces.SecurityAppArmor)
		c.Assert(err, IsNil)
		c.Assert(snippet, IsNil)
		// No extra seccomp permissions for slot
		snippet, err = s.iface.ConnectedSlotSnippet(plug, s.zigbeeAccessSlot, interfaces.SecuritySecComp)
		c.Assert(err, IsNil)
		c.Assert(snippet, IsNil)
		// No extra dbus permissions for slot
		snippet, err = s.iface.ConnectedSlotSnippet(plug, s.zigbeeAccessSlot, interfaces.SecurityDBus)
		c.Assert(err, IsNil)
		c.Assert(snippet, IsNil)
		// No extra udev permissions for slot
		snippet, err = s.iface.ConnectedSlotSnippet(plug, s.zigbeeAccessSlot, interfaces.SecurityUDev)
		c.Assert(err, IsNil)
		c.Assert(snippet, IsNil)
		// No extra mount permissions
		snippet, err = s.iface.ConnectedSlotSnippet(plug, s.zigbeeAccessSlot, interfaces.SecurityMount)
		c.Assert(err, IsNil)
		c.Assert(snippet, IsNil)
		// Other security types are not recognized
		snippet, err = s.iface.ConnectedSlotSnippet(plug, s.zigbeeAccessSlot, "foo")
		c.Assert(err, ErrorMatches, `unknown security system`)
		c.Assert(snippet, IsNil)
	}
}

func (s *ZigbeeDongleInterfaceSuite) TestPermanentPlugSnippetUnusedSecuritySystems(c *C) {
	for _, plug := range []*interfaces.Plug{s.genericPlug, s.specificPlug} {
		// No extra apparmor permissions for plug
		snippet, err := s.iface.PermanentPlugSnippet(plug, interfaces.SecurityAppArmor)
		c.Assert(err, IsNil)
		c.Assert(snippet, IsNil)
		// No extra seccomp permissions for plug
		snippet, err = s.iface.PermanentPlugSnippet(plug, interfaces.SecuritySecComp)
		c.Assert(err, IsNil)
		c.Assert(snippet, IsNil)
		// No extra dbus permissions for plug
		snippet, err = s.iface.PermanentPlugSnippet(plug, interfaces.SecurityDBus)
		c.Assert(err, IsNil)
		c.Assert(snippet, IsNil)
		// No extra udev permissions for plug
		snippet, err = s.iface.PermanentPlugSnippet(plug, interfaces.SecurityUDev)
		c.Assert(err, IsNil)
		c.Assert(snippet, IsNil)
		// no extra mount permissions
		snippet, err = s.iface.PermanentPlugSnippet(plug, interfaces.SecurityMount)
		c.Assert(err, IsNil)
		c.Assert(snippet, IsNil)
		// Other security types are not recognized
		snippet, err = s.iface.PermanentPlugSnippet(plug, "foo")
		c.Assert(err, ErrorMatches, `unknown security system`)
		c.Assert(snippet, IsNil)
	}
}

func (s *ZigbeeDongleInterfaceSuite) TestConnectedAppArmorSnippetForGenericPlug(c *C) {
	expectedAppArmorSnippet := []byte(nil)

	snippet, err := s.iface.ConnectedPlugSnippet(s.genericPlug, s.zigbeeAccessSlot, interfaces.SecurityAppArmor)
	c.Assert(err, IsNil)
	c.Assert(snippet, DeepEquals, expectedAppArmorSnippet, Commentf("\nexpected:\n%s\nfound:\n%s", expectedAppArmorSnippet, snippet))
}
func (s *ZigbeeDongleInterfaceSuite) TestConnectedUdevSnippetForGenericPlug(c *C) {
	expectedUdevSnippet := []byte(`IMPORT{builtin}="usb_id"
SUBSYSTEM=="tty", SUBSYSTEMS=="usb", ATTRS{idProduct}=="0003", ATTRS{idVendor}=="10c4", SYMLINK+="zigbee/$env{ID_SERIAL}"`)

	snippet, err := s.iface.ConnectedPlugSnippet(s.genericPlug, s.zigbeeAccessSlot, interfaces.SecurityUDev)
	c.Assert(err, IsNil)
	c.Assert(snippet, DeepEquals, expectedUdevSnippet, Commentf("\nexpected: %s\nfound: %s", expectedUdevSnippet, snippet))
}

func (s *ZigbeeDongleInterfaceSuite) TestConnectedAppArmorSnippetForSpecificPlug(c *C) {
	expectedAppArmorSnippet := []byte("/dev/** rw,\n")

	snippet, err := s.iface.ConnectedPlugSnippet(s.specificPlug, s.zigbeeAccessSlot, interfaces.SecurityAppArmor)
	c.Assert(err, IsNil)
	c.Assert(snippet, DeepEquals, expectedAppArmorSnippet, Commentf("\nexpected:\n%s\nfound:\n%s", expectedAppArmorSnippet, snippet))
}

func (s *ZigbeeDongleInterfaceSuite) TestConnectedUdevSnippetForSpecificPlug(c *C) {
	expectedUdevSnippet := []byte(`IMPORT{builtin}="usb_id"
SUBSYSTEM=="tty", SUBSYSTEMS=="usb", ATTRS{idProduct}=="1111", ATTRS{idVendor}=="2222", SYMLINK+="zigbee/$env{ID_SERIAL}", TAG+="snap_ubuntu-core-snap_app-with-specific-plug"
SUBSYSTEM=="tty", SUBSYSTEMS=="usb", ATTRS{idProduct}=="1111", ATTRS{idVendor}=="2222", SYMLINK+="zigbee/$env{ID_SERIAL}", TAG+="snap_ubuntu-core-snap_app2-with-specific-plug"
`)

	snippet, err := s.iface.ConnectedPlugSnippet(s.specificPlug, s.zigbeeAccessSlot, interfaces.SecurityUDev)
	c.Assert(err, IsNil)
	c.Assert(snippet, DeepEquals, expectedUdevSnippet, Commentf("\nexpected:\n%s\nfound:\n%s", expectedUdevSnippet, snippet))
}

func (s *ZigbeeDongleInterfaceSuite) TestAutoConnect(c *C) {
	c.Check(s.iface.AutoConnect(), Equals, false)
}
