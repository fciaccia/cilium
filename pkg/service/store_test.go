// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package service

import (
	"gopkg.in/check.v1"
)

type ServiceGenericSuite struct{}

var _ = check.Suite(&ServiceGenericSuite{})

func (s *ServiceGenericSuite) TestClusterService(c *check.C) {
	svc := NewClusterService("foo", "bar")
	svc.Cluster = "default"

	c.Assert(svc.Name, check.Equals, "foo")
	c.Assert(svc.Namespace, check.Equals, "bar")

	c.Assert(svc.String(), check.Equals, "default/bar:foo")

	b, err := svc.Marshal()
	c.Assert(err, check.IsNil)

	unmarshal := ClusterService{}
	err = unmarshal.Unmarshal(b)
	c.Assert(err, check.IsNil)
	c.Assert(svc, check.DeepEquals, unmarshal)

	c.Assert(svc.GetKeyName(), check.Equals, "default/bar/foo")
}
