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

package udev_test

import (
	"io/ioutil"
	"os"
	"path/filepath"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/backendtest"
	"github.com/snapcore/snapd/interfaces/udev"
	"github.com/snapcore/snapd/testutil"
)

type backendSuite struct {
	backendtest.BackendSuite

	udevadmCmd *testutil.MockCmd
}

var _ = Suite(&backendSuite{})

func (s *backendSuite) SetUpTest(c *C) {
	s.Backend = &udev.Backend{}

	s.BackendSuite.SetUpTest(c)

	// Mock away any real udev interaction
	s.udevadmCmd = testutil.MockCommand(c, "udevadm", "")
	// Prepare a directory for udev rules
	// NOTE: Normally this is a part of the OS snap.
	err := os.MkdirAll(dirs.SnapUdevRulesDir, 0700)
	c.Assert(err, IsNil)
}

func (s *backendSuite) TearDownTest(c *C) {
	s.udevadmCmd.Restore()

	s.BackendSuite.TearDownTest(c)
}

// Tests for Setup() and Remove()
func (s *backendSuite) TestName(c *C) {
	c.Check(s.Backend.Name(), Equals, "udev")
}

func (s *backendSuite) TestInstallingSnapWritesAndLoadsRules(c *C) {
	// NOTE: Hand out a permanent snippet so that .rules file is generated.
	s.Iface.PermanentSlotSnippetCallback = func(slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
		return []byte("dummy"), nil
	}
	for _, devMode := range []bool{true, false} {
		s.udevadmCmd.ForgetCalls()
		snapInfo := s.InstallSnap(c, devMode, backendtest.SambaYamlV1, 0)
		fname := filepath.Join(dirs.SnapUdevRulesDir, "70-snap.samba.smbd.rules")
		// file called "70-snap.sambda.smbd.rules" was created
		_, err := os.Stat(fname)
		c.Check(err, IsNil)
		// udevadm was used to reload rules and re-run triggers
		c.Check(s.udevadmCmd.Calls(), DeepEquals, [][]string{
			{"udevadm", "control", "--reload-rules"},
			{"udevadm", "trigger"},
		})
		s.RemoveSnap(c, snapInfo)
	}
}

func (s *backendSuite) TestSecurityIsStable(c *C) {
	// NOTE: Hand out a permanent snippet so that .rules file is generated.
	s.Iface.PermanentSlotSnippetCallback = func(slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
		return []byte("dummy"), nil
	}
	for _, devMode := range []bool{true, false} {
		snapInfo := s.InstallSnap(c, devMode, backendtest.SambaYamlV1, 0)
		s.udevadmCmd.ForgetCalls()
		err := s.Backend.Setup(snapInfo, devMode, s.Repo)
		c.Assert(err, IsNil)
		// rules are not re-loaded when nothing changes
		c.Check(s.udevadmCmd.Calls(), HasLen, 0)
		s.RemoveSnap(c, snapInfo)
	}
}

func (s *backendSuite) TestRemovingSnapRemovesAndReloadsRules(c *C) {
	// NOTE: Hand out a permanent snippet so that .rules file is generated.
	s.Iface.PermanentSlotSnippetCallback = func(slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
		return []byte("dummy"), nil
	}
	for _, devMode := range []bool{true, false} {
		snapInfo := s.InstallSnap(c, devMode, backendtest.SambaYamlV1, 0)
		s.udevadmCmd.ForgetCalls()
		s.RemoveSnap(c, snapInfo)
		fname := filepath.Join(dirs.SnapUdevRulesDir, "70-snap.samba.smbd.rules")
		// file called "70-snap.sambda.smbd.rules" was removed
		_, err := os.Stat(fname)
		c.Check(os.IsNotExist(err), Equals, true)
		// udevadm was used to reload rules and re-run triggers
		c.Check(s.udevadmCmd.Calls(), DeepEquals, [][]string{
			{"udevadm", "control", "--reload-rules"},
			{"udevadm", "trigger"},
		})
	}
}

func (s *backendSuite) TestUpdatingSnapToOneWithMoreApps(c *C) {
	// NOTE: Hand out a permanent snippet so that .rules file is generated.
	s.Iface.PermanentSlotSnippetCallback = func(slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
		return []byte("dummy"), nil
	}
	for _, devMode := range []bool{true, false} {
		snapInfo := s.InstallSnap(c, devMode, backendtest.SambaYamlV1, 0)
		s.udevadmCmd.ForgetCalls()
		snapInfo = s.UpdateSnap(c, snapInfo, devMode, backendtest.SambaYamlV1WithNmbd, 0)
		// NOTE the application is "nmbd", not "smbd"
		fname := filepath.Join(dirs.SnapUdevRulesDir, "70-snap.samba.nmbd.rules")
		// file called "70-snap.sambda.nmbd.rules" was created
		_, err := os.Stat(fname)
		c.Check(err, IsNil)
		// udevadm was used to reload rules and re-run triggers
		c.Check(s.udevadmCmd.Calls(), DeepEquals, [][]string{
			{"udevadm", "control", "--reload-rules"},
			{"udevadm", "trigger"},
		})
		s.RemoveSnap(c, snapInfo)
	}
}

func (s *backendSuite) TestUpdatingSnapToOneWithFewerApps(c *C) {
	// NOTE: Hand out a permanent snippet so that .rules file is generated.
	s.Iface.PermanentSlotSnippetCallback = func(slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
		return []byte("dummy"), nil
	}
	for _, devMode := range []bool{true, false} {
		snapInfo := s.InstallSnap(c, devMode, backendtest.SambaYamlV1WithNmbd, 0)
		s.udevadmCmd.ForgetCalls()
		snapInfo = s.UpdateSnap(c, snapInfo, devMode, backendtest.SambaYamlV1, 0)
		// NOTE the application is "nmbd", not "smbd"
		fname := filepath.Join(dirs.SnapUdevRulesDir, "70-snap.samba.nmbd.rules")
		// file called "70-snap.sambda.nmbd.rules" was removed
		_, err := os.Stat(fname)
		c.Check(os.IsNotExist(err), Equals, true)
		// udevadm was used to reload rules and re-run triggers
		c.Check(s.udevadmCmd.Calls(), DeepEquals, [][]string{
			{"udevadm", "control", "--reload-rules"},
			{"udevadm", "trigger"},
		})
		s.RemoveSnap(c, snapInfo)
	}
}

func (s *backendSuite) TestCombineSnippetsWithActualSnippets(c *C) {
	// NOTE: Hand out a permanent snippet so that .rules file is generated.
	s.Iface.PermanentSlotSnippetCallback = func(slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
		return []byte("dummy"), nil
	}
	for _, devMode := range []bool{false, true} {
		snapInfo := s.InstallSnap(c, devMode, backendtest.SambaYamlV1, 0)
		fname := filepath.Join(dirs.SnapUdevRulesDir, "70-snap.samba.smbd.rules")
		data, err := ioutil.ReadFile(fname)
		c.Assert(err, IsNil)
		c.Check(string(data), Equals, "# This file is automatically generated.\ndummy\n")
		stat, err := os.Stat(fname)
		c.Check(stat.Mode(), Equals, os.FileMode(0644))
		s.RemoveSnap(c, snapInfo)
	}
}

func (s *backendSuite) TestCombineSnippetsWithoutAnySnippets(c *C) {
	for _, devMode := range []bool{false, true} {
		snapInfo := s.InstallSnap(c, devMode, backendtest.SambaYamlV1, 0)
		fname := filepath.Join(dirs.SnapUdevRulesDir, "70-snap.samba.smbd.rules")
		_, err := os.Stat(fname)
		// Without any snippets, there the .rules file is not created.
		c.Check(os.IsNotExist(err), Equals, true)
		s.RemoveSnap(c, snapInfo)
	}
}
