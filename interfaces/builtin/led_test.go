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
	"bytes"
	"fmt"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/builtin"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/testutil"
)

type LedInterfaceSuite struct {
	testutil.BaseTest
	iface             interfaces.Interface
	testLEDSlot       *interfaces.Slot
	badPathSlot       *interfaces.Slot
	parentDirPathSlot *interfaces.Slot
	missingPathSlot   *interfaces.Slot
	badInterfaceSlot  *interfaces.Slot
	plug              *interfaces.Plug
	badInterfacePlug  *interfaces.Plug
}

var _ = Suite(&LedInterfaceSuite{
	iface: &builtin.LedInterface{},
})

func (s *LedInterfaceSuite) SetUpTest(c *C) {
	info, err := snap.InfoFromSnapYaml([]byte(`
name: ubuntu-core
slots:
    test-led:
        interface: led
        path: /sys/class/gpio/gpio13/value
    missing-path: led
    bad-path:
        interface: led
        path: path
    parent-dir-path:
        interface: led
        path: "/sys/class/gpio/../value"
    bad-interface: other-interface
plugs:
    plug: led
    bad-interface: other-interface
`))
	c.Assert(err, IsNil)
	s.testLEDSlot = &interfaces.Slot{SlotInfo: info.Slots["test-led"]}
	s.missingPathSlot = &interfaces.Slot{SlotInfo: info.Slots["missing-path"]}
	s.badPathSlot = &interfaces.Slot{SlotInfo: info.Slots["bad-path"]}
	s.parentDirPathSlot = &interfaces.Slot{SlotInfo: info.Slots["parent-dir-path"]}
	s.badInterfaceSlot = &interfaces.Slot{SlotInfo: info.Slots["bad-interface"]}
	s.plug = &interfaces.Plug{PlugInfo: info.Plugs["plug"]}
	s.badInterfacePlug = &interfaces.Plug{PlugInfo: info.Plugs["bad-interface"]}
}

func (s *LedInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "led")
}

func (s *LedInterfaceSuite) TestSanitizeSlot(c *C) {
	// Both LED and GPIO slots are accepted
	err := s.iface.SanitizeSlot(s.testLEDSlot)
	c.Assert(err, IsNil)
	// Slots without the "path" attribute are rejected.
	err = s.iface.SanitizeSlot(s.missingPathSlot)
	c.Assert(err, ErrorMatches,
		"led must contain the path attribute")
	// Slots without the "path" attribute are rejected.
	err = s.iface.SanitizeSlot(s.parentDirPathSlot)
	c.Assert(err, ErrorMatches,
		"led can only point at a value file")
	// Slots with incorrect value of the "path" attribute are rejected.
	err = s.iface.SanitizeSlot(s.badPathSlot)
	c.Assert(err, ErrorMatches,
		"led can only point at a value file")
	// It is impossible to use "led" interface to sanitize slots with other interfaces.
	c.Assert(func() { s.iface.SanitizeSlot(s.badInterfaceSlot) }, PanicMatches,
		`slot is not of interface "led"`)
}

func (s *LedInterfaceSuite) TestSanitizePlug(c *C) {
	err := s.iface.SanitizePlug(s.plug)
	c.Assert(err, IsNil)
	// It is impossible to use "led" interface to sanitize plugs of different interface.
	c.Assert(func() { s.iface.SanitizePlug(s.badInterfacePlug) }, PanicMatches,
		`plug is not of interface "led"`)
}

func (s *LedInterfaceSuite) TestPlugSnippetHandlesSymlinkErrors(c *C) {
	// Symbolic link traversal is handled correctly
	builtin.MockEvalSymlinks(&s.BaseTest, func(path string) (string, error) {
		return "", fmt.Errorf("broken symbolic link")
	})
	snippet, err := s.iface.ConnectedPlugSnippet(s.plug, s.testLEDSlot, interfaces.SecurityAppArmor)
	c.Assert(err, ErrorMatches, "cannot compute plug security snippet: broken symbolic link")
	c.Assert(snippet, IsNil)
}

func (s *LedInterfaceSuite) TestPlugSnippetDereferencesSymlinks(c *C) {
	// Use a fake (successful) dereferencing function for the remainder of the test.
	builtin.MockEvalSymlinks(&s.BaseTest, func(path string) (string, error) {
		return "(dereferenced)" + path, nil
	})
	// Extra apparmor permission to access GPIO value
	// The path uses dereferenced symbolic links.
	snippet, err := s.iface.ConnectedPlugSnippet(s.plug, s.testLEDSlot, interfaces.SecurityAppArmor)
	c.Assert(err, IsNil)
	c.Assert(snippet, DeepEquals, []byte(
		"(dereferenced)/sys/class/gpio/gpio13/value rwk,\n"))
}

func (s *LedInterfaceSuite) TestPermanentPlugSecurityDoesNotContainSlotSecurity(c *C) {
	// Use a fake (successful) dereferencing function for the remainder of the test.
	builtin.MockEvalSymlinks(&s.BaseTest, func(path string) (string, error) {
		return path, nil
	})
	var err error
	var slotSnippet, plugSnippet []byte
	plugSnippet, err = s.iface.PermanentPlugSnippet(s.plug, interfaces.SecurityAppArmor)
	c.Assert(err, IsNil)
	slotSnippet, err = s.iface.PermanentSlotSnippet(s.testLEDSlot, interfaces.SecurityAppArmor)
	c.Assert(err, IsNil)
	// Ensure that we don't accidentally give plug-side permissions to slot-side.
	c.Assert(bytes.Contains(plugSnippet, slotSnippet), Equals, false)
}

func (s *LedInterfaceSuite) TestConnectedPlugSnippetPanicksOnUnsanitizedSlots(c *C) {
	// Unsanitized slots should never be used and cause a panic.
	c.Assert(func() {
		s.iface.ConnectedPlugSnippet(s.plug, s.missingPathSlot, interfaces.SecurityAppArmor)
	}, PanicMatches, "slot is not sanitized")
}

func (s *LedInterfaceSuite) TestConnectedPlugSnippetUnusedSecuritySystems(c *C) {
	// No extra seccomp permissions for plug
	snippet, err := s.iface.ConnectedPlugSnippet(s.plug, s.testLEDSlot, interfaces.SecuritySecComp)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra dbus permissions for plug
	snippet, err = s.iface.ConnectedPlugSnippet(s.plug, s.testLEDSlot, interfaces.SecurityDBus)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra udev permissions for plug
	snippet, err = s.iface.ConnectedPlugSnippet(s.plug, s.testLEDSlot, interfaces.SecurityUDev)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra udev permissions for plug
	snippet, err = s.iface.ConnectedPlugSnippet(s.plug, s.testLEDSlot, interfaces.SecurityUDev)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// Other security types are not recognized
	snippet, err = s.iface.ConnectedPlugSnippet(s.plug, s.testLEDSlot, "foo")
	c.Assert(err, ErrorMatches, `unknown security system`)
	c.Assert(snippet, IsNil)
}

func (s *LedInterfaceSuite) TestPermanentPlugSnippetUnusedSecuritySystems(c *C) {
	// No extra seccomp permissions for plug
	snippet, err := s.iface.PermanentPlugSnippet(s.plug, interfaces.SecuritySecComp)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra dbus permissions for plug
	snippet, err = s.iface.PermanentPlugSnippet(s.plug, interfaces.SecurityDBus)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra udev permissions for plug
	snippet, err = s.iface.PermanentPlugSnippet(s.plug, interfaces.SecurityUDev)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra udev permissions for plug
	snippet, err = s.iface.PermanentPlugSnippet(s.plug, interfaces.SecurityUDev)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// Other security types are not recognized
	snippet, err = s.iface.PermanentPlugSnippet(s.plug, "foo")
	c.Assert(err, ErrorMatches, `unknown security system`)
	c.Assert(snippet, IsNil)
}

func (s *LedInterfaceSuite) TestPermanentSlotSnippetGivesExtraPermissionsToConfigureGPIOs(c *C) {
	// Extra apparmor permission to provide GPIOs
	expectedGPIOSnippet := []byte(`
/sys/class/gpio/export rw,
/sys/class/gpio/unexport rw,
/sys/class/gpio/gpio[0-9]+/direction rw,
`)
	snippet, err := s.iface.PermanentSlotSnippet(s.testLEDSlot, interfaces.SecurityAppArmor)
	c.Assert(err, IsNil)
	c.Assert(snippet, DeepEquals, expectedGPIOSnippet)
}

func (s *LedInterfaceSuite) TestPermanentSlotSnippetPanicksOnUnsanitizedSlots(c *C) {
	// Unsanitized slots should never be used and cause a panic.
	c.Assert(func() {
		s.iface.PermanentSlotSnippet(s.missingPathSlot, interfaces.SecurityAppArmor)
	}, PanicMatches, "slot is not sanitized")
}

func (s *LedInterfaceSuite) TestConnectedSlotSnippetUnusedSecuritySystems(c *C) {
	// No extra seccomp permissions for slot
	snippet, err := s.iface.ConnectedSlotSnippet(s.plug, s.testLEDSlot, interfaces.SecuritySecComp)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra dbus permissions for slot
	snippet, err = s.iface.ConnectedSlotSnippet(s.plug, s.testLEDSlot, interfaces.SecurityDBus)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra udev permissions for slot
	snippet, err = s.iface.ConnectedSlotSnippet(s.plug, s.testLEDSlot, interfaces.SecurityUDev)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// Other security types are not recognized
	snippet, err = s.iface.ConnectedSlotSnippet(s.plug, s.testLEDSlot, "foo")
	c.Assert(err, ErrorMatches, `unknown security system`)
	c.Assert(snippet, IsNil)
}

func (s *LedInterfaceSuite) TestPermanentSlotSnippetUnusedSecuritySystems(c *C) {
	// No extra seccomp permissions for slot
	snippet, err := s.iface.PermanentSlotSnippet(s.testLEDSlot, interfaces.SecuritySecComp)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra dbus permissions for slot
	snippet, err = s.iface.PermanentSlotSnippet(s.testLEDSlot, interfaces.SecurityDBus)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// No extra udev permissions for slot
	snippet, err = s.iface.PermanentSlotSnippet(s.testLEDSlot, interfaces.SecurityUDev)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	// Other security types are not recognized
	snippet, err = s.iface.PermanentSlotSnippet(s.testLEDSlot, "foo")
	c.Assert(err, ErrorMatches, `unknown security system`)
	c.Assert(snippet, IsNil)
}

func (s *LedInterfaceSuite) TestAutoConnect(c *C) {
	c.Check(s.iface.AutoConnect(), Equals, false)
}
