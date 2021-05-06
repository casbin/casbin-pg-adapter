package pgadapter

import (
	"os"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	"github.com/go-pg/pg/v10"
	"github.com/stretchr/testify/suite"
)

// AdapterTestSuite tests all functionalities of Adapter
type AdapterTestSuite struct {
	suite.Suite
	e *casbin.Enforcer
	a *Adapter
}

func (s *AdapterTestSuite) assertPolicy(expected, res [][]string) {
	s.T().Helper()
	s.Assert().True(util.Array2DEquals(expected, res), "Policy Got: %v, supposed to be %v", res, expected)
}

func (s *AdapterTestSuite) dropCasbinDB() {
	opts, err := pg.ParseURL(os.Getenv("PG_CONN"))
	s.Require().NoError(err)
	db := pg.Connect(opts)
	defer db.Close()
	db.Exec("DROP DATABASE casbin")
}

func (s *AdapterTestSuite) SetupTest() {
	s.dropCasbinDB()

	var err error
	s.a, err = NewAdapter(os.Getenv("PG_CONN"))
	s.Require().NoError(err)

	// This is a trick to save the current policy to the DB.
	// We can't call e.SavePolicy() because the adapter in the enforcer is still the file adapter.
	// The current policy means the policy in the Casbin enforcer (aka in memory).
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	s.Require().NoError(err)
	err = s.a.SavePolicy(e.GetModel())
	s.Require().NoError(err)

	s.e, err = casbin.NewEnforcer("examples/rbac_model.conf", s.a)
	s.Require().NoError(err)
}

func (s *AdapterTestSuite) TearDownTest() {
	err := s.a.Close()
	s.Require().NoError(err)
}

func (s *AdapterTestSuite) TestSaveLoad() {
	s.Assert().False(s.e.IsFiltered())
	s.assertPolicy(
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
		s.e.GetPolicy(),
	)
}

func (s *AdapterTestSuite) TestAutoSave() {
	// AutoSave is enabled by default.
	// Now we disable it.
	s.e.EnableAutoSave(false)

	// Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
	// it doesn't affect the policy in the storage.
	_, err := s.e.AddPolicy("alice", "data1", "write")
	s.Require().NoError(err)
	// Reload the policy from the storage to see the effect.
	err = s.e.LoadPolicy()
	s.Require().NoError(err)
	// This is still the original policy.
	s.assertPolicy(
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
		s.e.GetPolicy(),
	)

	// Now we enable the AutoSave.
	s.e.EnableAutoSave(true)

	// Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
	// but also affects the policy in the storage.
	_, err = s.e.AddPolicy("alice", "data1", "write")
	s.Require().NoError(err)
	// Reload the policy from the storage to see the effect.
	err = s.e.LoadPolicy()
	s.Require().NoError(err)
	// The policy has a new rule: {"alice", "data1", "write"}.
	s.assertPolicy(
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data1", "write"}},
		s.e.GetPolicy(),
	)

	// Aditional AddPolicy have no effect
	_, err = s.e.AddPolicy("alice", "data1", "write")
	s.Require().NoError(err)
	err = s.e.LoadPolicy()
	s.Require().NoError(err)
	s.assertPolicy(
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data1", "write"}},
		s.e.GetPolicy(),
	)

	_, err = s.e.AddPolicies([][]string{
		{"bob", "data2", "read"},
		{"alice", "data2", "write"},
		{"alice", "data2", "read"},
		{"bob", "data1", "write"},
		{"bob", "data1", "read"},
	})
	s.Require().NoError(err)
	// Reload the policy from the storage to see the effect.
	err = s.e.LoadPolicy()
	s.Require().NoError(err)
	// The policy has a new rule: {"alice", "data1", "write"}.
	s.assertPolicy(
		[][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"data2_admin", "data2", "read"},
			{"data2_admin", "data2", "write"},
			{"alice", "data1", "write"},
			{"bob", "data2", "read"},
			{"alice", "data2", "write"},
			{"alice", "data2", "read"},
			{"bob", "data1", "write"},
			{"bob", "data1", "read"},
		},
		s.e.GetPolicy(),
	)

	s.Require().NoError(err)
}

func (s *AdapterTestSuite) TestConstructorOptions() {
	opts, err := pg.ParseURL(os.Getenv("PG_CONN"))
	s.Require().NoError(err)

	a, err := NewAdapter(opts)
	s.Require().NoError(err)
	defer a.Close()

	s.e, err = casbin.NewEnforcer("examples/rbac_model.conf", a)
	s.Require().NoError(err)

	s.assertPolicy(
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
		s.e.GetPolicy(),
	)
}

func (s *AdapterTestSuite) TestRemovePolicy() {
	_, err := s.e.RemovePolicy("alice", "data1", "read")
	s.Require().NoError(err)

	s.assertPolicy(
		[][]string{{"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
		s.e.GetPolicy(),
	)

	err = s.e.LoadPolicy()
	s.Require().NoError(err)

	s.assertPolicy(
		[][]string{{"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
		s.e.GetPolicy(),
	)

	_, err = s.e.RemovePolicies([][]string{
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	})
	s.Require().NoError(err)

	s.assertPolicy(
		[][]string{{"bob", "data2", "write"}},
		s.e.GetPolicy(),
	)
}

func (s *AdapterTestSuite) TestRemoveFilteredPolicy() {
	_, err := s.e.RemoveFilteredPolicy(0, "", "data2")
	s.Require().NoError(err)

	s.assertPolicy(
		[][]string{{"alice", "data1", "read"}},
		s.e.GetPolicy(),
	)

	err = s.e.LoadPolicy()
	s.Require().NoError(err)

	s.assertPolicy(
		[][]string{{"alice", "data1", "read"}},
		s.e.GetPolicy(),
	)
}

func (s *AdapterTestSuite) TestLoadFilteredPolicy() {
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", s.a)
	s.Require().NoError(err)

	err = e.LoadFilteredPolicy(&Filter{
		P: []string{"", "", "read"},
	})
	s.Require().NoError(err)
	s.Assert().True(e.IsFiltered())
	s.assertPolicy(
		[][]string{{"alice", "data1", "read"}, {"data2_admin", "data2", "read"}},
		e.GetPolicy(),
	)
}

func (s *AdapterTestSuite) TestLoadFilteredGroupingPolicy() {
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", s.a)
	s.Require().NoError(err)

	err = e.LoadFilteredPolicy(&Filter{
		G: []string{"bob"},
	})
	s.Require().NoError(err)
	s.Assert().True(e.IsFiltered())
	s.assertPolicy([][]string{}, e.GetGroupingPolicy())

	e, err = casbin.NewEnforcer("examples/rbac_model.conf", s.a)
	s.Require().NoError(err)

	err = e.LoadFilteredPolicy(&Filter{
		G: []string{"alice"},
	})
	s.Require().NoError(err)
	s.Assert().True(e.IsFiltered())
	s.assertPolicy([][]string{{"alice", "data2_admin"}}, e.GetGroupingPolicy())
}

func (s *AdapterTestSuite) TestLoadFilteredPolicyNilFilter() {
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", s.a)
	s.Require().NoError(err)

	err = e.LoadFilteredPolicy(nil)
	s.Require().NoError(err)

	s.Assert().False(e.IsFiltered())
	s.assertPolicy(
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
		s.e.GetPolicy(),
	)
}

func (s *AdapterTestSuite) TestSavePolicyClearPreviousData() {
	s.e.EnableAutoSave(false)
	policies := s.e.GetPolicy()
	// clone slice to avoid shufling elements
	policies = append(policies[:0:0], policies...)
	for _, p := range policies {
		_, err := s.e.RemovePolicy(p)
		s.Require().NoError(err)
	}
	policies = s.e.GetGroupingPolicy()
	policies = append(policies[:0:0], policies...)
	for _, p := range policies {
		_, err := s.e.RemoveGroupingPolicy(p)
		s.Require().NoError(err)
	}
	s.assertPolicy(
		[][]string{},
		s.e.GetPolicy(),
	)

	err := s.e.SavePolicy()
	s.Require().NoError(err)

	err = s.e.LoadPolicy()
	s.Require().NoError(err)
	s.assertPolicy(
		[][]string{},
		s.e.GetPolicy(),
	)
}

func (s *AdapterTestSuite) TestUpdatePolicy() {
	var err error
	s.e, err = casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	s.Require().NoError(err)

	s.e.SetAdapter(s.a)

	err = s.e.SavePolicy()
	s.Require().NoError(err)

	_, err = s.e.UpdatePolicies([][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}}, [][]string{{"bob", "data1", "read"}, {"alice", "data2", "write"}})
	s.Require().NoError(err)

	err = s.e.LoadPolicy()
	s.Require().NoError(err)

	s.assertPolicy(s.e.GetPolicy(), [][]string{{"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"bob", "data1", "read"}, {"alice", "data2", "write"}})
}

func (s *AdapterTestSuite) TestUpdatePolicyWithLoadFilteredPolicy() {
	var err error
	s.e, err = casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	s.Require().NoError(err)

	s.e.SetAdapter(s.a)

	err = s.e.SavePolicy()
	s.Require().NoError(err)

	err = s.e.LoadFilteredPolicy(&Filter{P: []string{"data2_admin"}})
	s.Require().NoError(err)

	_, err = s.e.UpdatePolicies(s.e.GetPolicy(), [][]string{{"bob", "data2", "read"}, {"alice", "data2", "write"}})
	s.Require().NoError(err)

	err = s.e.LoadPolicy()
	s.Require().NoError(err)

	s.assertPolicy(s.e.GetPolicy(), [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"bob", "data2", "read"}, {"alice", "data2", "write"}})
}

func (s *AdapterTestSuite) TestUpdateFilteredPolicies() {

	var err error
	s.e, err = casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	s.Require().NoError(err)

	s.e.SetAdapter(s.a)

	err = s.e.SavePolicy()
	s.Require().NoError(err)

	err = s.a.UpdateFilteredPolicies("p", "p", [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}}, [][]string{{"alice", "data2", "write"}, {"bob", "data1", "read"}})
	s.Require().NoError(err)

	err = s.e.LoadPolicy()
	s.Require().NoError(err)

	s.assertPolicy(s.e.GetPolicy(), [][]string{{"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data2", "write"}, {"bob", "data1", "read"}})
}
func TestAdapterTestSuite(t *testing.T) {
	suite.Run(t, new(AdapterTestSuite))
}
