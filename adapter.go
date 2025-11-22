package pgadapter

import (
	"context"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
	"github.com/mmcloughlin/meow"
)

const DefaultTableName = "casbin_rule"
const DefaultDatabaseName = "casbin"

// CasbinRule represents a rule in Casbin.
type CasbinRule struct {
	tableName struct{} `pg:"_"`
	ID        string
	Ptype     string
	V0        string `pg:",use_zero"`
	V1        string `pg:",use_zero"`
	V2        string `pg:",use_zero"`
	V3        string `pg:",use_zero"`
	V4        string `pg:",use_zero"`
	V5        string `pg:",use_zero"`
}

type Filter struct {
	P []string
	G []string
}

// Adapter represents the github.com/go-pg/pg adapter for policy storage.
type Adapter struct {
	db              *pg.DB
	tableName       string
	skipTableCreate bool
	filtered        bool
}

type Option func(a *Adapter)

// NewAdapter is the constructor for Adapter.
// param:arg should be a PostgreS URL string or of type *pg.Options
// param:dbname is the name of the database to use and can is optional.
// If no dbname is provided, the default database name is "casbin" which will be created automatically.
// If arg is *pg.Options, the arg.Database field is omitted and will be modified according to dbname
func NewAdapter(arg interface{}, dbname ...string) (*Adapter, error) {
	var db *pg.DB
	var err error

	if len(dbname) > 0 {
		db, err = createCasbinDatabase(arg, dbname[0])
	} else {
		db, err = createCasbinDatabase(arg, DefaultDatabaseName)
	}

	if err != nil {
		return nil, fmt.Errorf("pgadapter.NewAdapter: %v", err)
	}

	a := &Adapter{db: db, tableName: DefaultTableName}

	if err := a.createTableifNotExists(); err != nil {
		return nil, fmt.Errorf("pgadapter.NewAdapter: %v", err)
	}

	return a, nil
}

// NewAdapterByDB creates new Adapter by using existing DB connection
// creates table from CasbinRule struct if it doesn't exist
func NewAdapterByDB(db *pg.DB, opts ...Option) (*Adapter, error) {
	a := &Adapter{db: db, tableName: DefaultTableName}
	for _, opt := range opts {
		opt(a)
	}

	if !a.skipTableCreate {
		if err := a.createTableifNotExists(); err != nil {
			return nil, fmt.Errorf("pgadapter.NewAdapter: %v", err)
		}
	}
	return a, nil
}

// WithTableName can be used to pass custom table name for Casbin rules
func WithTableName(tableName string) Option {
	return func(a *Adapter) {
		a.tableName = tableName
	}
}

// SkipTableCreate skips the table creation step when the adapter starts
// If the Casbin rules table does not exist, it will lead to issues when using the adapter
func SkipTableCreate() Option {
	return func(a *Adapter) {
		a.skipTableCreate = true
	}
}

func createCasbinDatabase(arg interface{}, dbname string) (*pg.DB, error) {
	var opts *pg.Options
	var err error
	if connURL, ok := arg.(string); ok {
		opts, err = pg.ParseURL(connURL)
		if err != nil {
			return nil, err
		}
	} else {
		opts, ok = arg.(*pg.Options)
		if !ok {
			return nil, fmt.Errorf("must pass in a PostgreS URL string or an instance of *pg.Options, received %T instead", arg)
		}
	}

	db := pg.Connect(opts)
	defer db.Close()

	_, err = db.Exec(fmt.Sprintf("CREATE DATABASE %s", dbname))
	if err != nil && !strings.Contains(err.Error(), "42P04") {
		return nil, err
	}
	db.Close()

	opts.Database = dbname
	db = pg.Connect(opts)

	return db, nil
}

// Close close database connection
func (a *Adapter) Close() error {
	if a != nil && a.db != nil {
		return a.db.Close()
	}
	return nil
}

func (a *Adapter) createTableifNotExists() error {
	err := a.db.Model((*CasbinRule)(nil)).Table(a.tableName).CreateTable(&orm.CreateTableOptions{
		Temp:        false,
		IfNotExists: true,
	})
	if err != nil {
		return err
	}
	return nil
}

func (r *CasbinRule) String() string {
	const prefixLine = ", "
	var sb strings.Builder

	sb.Grow(
		len(r.Ptype) +
			len(r.V0) + len(r.V1) + len(r.V2) +
			len(r.V3) + len(r.V4) + len(r.V5),
	)

	sb.WriteString(r.Ptype)
	
	// Build array of values to determine the last non-empty position
	values := []string{r.V0, r.V1, r.V2, r.V3, r.V4, r.V5}
	lastIndex := -1
	for i := len(values) - 1; i >= 0; i-- {
		if values[i] != "" {
			lastIndex = i
			break
		}
	}
	
	// Include all values up to and including the last non-empty one
	// This preserves empty strings in the middle while trimming trailing empty strings
	for i := 0; i <= lastIndex; i++ {
		sb.WriteString(prefixLine)
		sb.WriteString(values[i])
	}

	return sb.String()
}

// LoadPolicy loads policy from database.
func (a *Adapter) LoadPolicy(model model.Model) error {
	var lines []*CasbinRule

	if err := a.db.Model(&lines).Table(a.tableName).Select(); err != nil {
		return err
	}

	for _, line := range lines {
		err := persist.LoadPolicyLine(line.String(), model)
		if err != nil {
			return err
		}
	}

	a.filtered = false

	return nil
}

func policyID(ptype string, rule []string) string {
	data := strings.Join(append([]string{ptype}, rule...), ",")
	sum := meow.Checksum(0, []byte(data))
	return fmt.Sprintf("%x", sum)
}

func savePolicyLine(ptype string, rule []string) *CasbinRule {
	line := &CasbinRule{Ptype: ptype}

	l := len(rule)
	if l > 0 {
		line.V0 = rule[0]
	}
	if l > 1 {
		line.V1 = rule[1]
	}
	if l > 2 {
		line.V2 = rule[2]
	}
	if l > 3 {
		line.V3 = rule[3]
	}
	if l > 4 {
		line.V4 = rule[4]
	}
	if l > 5 {
		line.V5 = rule[5]
	}

	line.ID = policyID(ptype, rule)

	return line
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {
	tx, err := a.db.Begin()
	if err != nil {
		return fmt.Errorf("start DB transaction: %v", err)
	}
	defer tx.Close()

	_, err = tx.Model((*CasbinRule)(nil)).Table(a.tableName).Where("id IS NOT NULL").Delete()
	if err != nil {
		return err
	}

	var lines []*CasbinRule

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	for _, line := range lines {
		_, err = tx.Model(line).Table(a.tableName).
			OnConflict("DO NOTHING").
			Insert()
		if err != nil {
			return err
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("commit DB transaction: %v", err)
	}

	return nil
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	err := a.db.RunInTransaction(context.Background(), func(tx *pg.Tx) error {
		_, err := a.db.Model(line).
			Table(a.tableName).
			OnConflict("DO NOTHING").
			Insert()

		return err
	})

	return err
}

// AddPolicies adds policy rules to the storage.
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	var lines []*CasbinRule
	for _, rule := range rules {
		line := savePolicyLine(ptype, rule)
		lines = append(lines, line)
	}

	err := a.db.RunInTransaction(context.Background(), func(tx *pg.Tx) error {
		_, err := tx.Model(&lines).
			Table(a.tableName).
			OnConflict("DO NOTHING").
			Insert()
		return err
	})

	return err
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	err := a.db.RunInTransaction(context.Background(), func(tx *pg.Tx) error {
		_, err := a.db.Model(line).Table(a.tableName).WherePK().Delete()
		return err
	})

	return err
}

// RemovePolicies removes policy rules from the storage.
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	var lines []*CasbinRule
	for _, rule := range rules {
		line := savePolicyLine(ptype, rule)
		lines = append(lines, line)
	}

	err := a.db.RunInTransaction(context.Background(), func(tx *pg.Tx) error {
		_, err := tx.Model(&lines).Table(a.tableName).
			Delete()
		return err
	})

	return err
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	query := a.db.Model((*CasbinRule)(nil)).Table(a.tableName).Where("ptype = ?", ptype)

	idx := fieldIndex + len(fieldValues)
	if fieldIndex <= 0 && idx > 0 && fieldValues[0-fieldIndex] != "" {
		query = query.Where("v0 = ?", fieldValues[0-fieldIndex])
	}
	if fieldIndex <= 1 && idx > 1 && fieldValues[1-fieldIndex] != "" {
		query = query.Where("v1 = ?", fieldValues[1-fieldIndex])
	}
	if fieldIndex <= 2 && idx > 2 && fieldValues[2-fieldIndex] != "" {
		query = query.Where("v2 = ?", fieldValues[2-fieldIndex])
	}
	if fieldIndex <= 3 && idx > 3 && fieldValues[3-fieldIndex] != "" {
		query = query.Where("v3 = ?", fieldValues[3-fieldIndex])
	}
	if fieldIndex <= 4 && idx > 4 && fieldValues[4-fieldIndex] != "" {
		query = query.Where("v4 = ?", fieldValues[4-fieldIndex])
	}
	if fieldIndex <= 5 && idx > 5 && fieldValues[5-fieldIndex] != "" {
		query = query.Where("v5 = ?", fieldValues[5-fieldIndex])
	}

	err := a.db.RunInTransaction(context.Background(), func(tx *pg.Tx) error {
		_, err := query.Delete()
		return err
	})

	return err
}

func (a *Adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	if filter == nil {
		return a.LoadPolicy(model)
	}

	filterValue, ok := filter.(*Filter)
	if !ok {
		return fmt.Errorf("invalid filter type")
	}
	err := a.loadFilteredPolicy(model, filterValue, persist.LoadPolicyLine)
	if err != nil {
		return err
	}
	a.filtered = true
	return nil
}

func buildQuery(query *orm.Query, values []string) (*orm.Query, error) {
	for ind, v := range values {
		if v == "" {
			continue
		}
		switch ind {
		case 0:
			query = query.Where("v0 = ?", v)
		case 1:
			query = query.Where("v1 = ?", v)
		case 2:
			query = query.Where("v2 = ?", v)
		case 3:
			query = query.Where("v3 = ?", v)
		case 4:
			query = query.Where("v4 = ?", v)
		case 5:
			query = query.Where("v5 = ?", v)
		default:
			return nil, fmt.Errorf("filter has more values than expected, should not exceed 6 values")
		}
	}
	return query, nil
}

func (a *Adapter) loadFilteredPolicy(model model.Model, filter *Filter, handler func(string, model.Model) error) error {
	if filter.P != nil {
		lines := []*CasbinRule{}

		query := a.db.Model(&lines).Table(a.tableName).Where("ptype = 'p'")
		query, err := buildQuery(query, filter.P)
		if err != nil {
			return err
		}
		err = query.Select()
		if err != nil {
			return err
		}

		for _, line := range lines {
			handler(line.String(), model)
		}
	}
	if filter.G != nil {
		lines := []*CasbinRule{}

		query := a.db.Model(&lines).Table(a.tableName).Where("ptype = 'g'")
		query, err := buildQuery(query, filter.G)
		if err != nil {
			return err
		}
		err = query.Select()
		if err != nil {
			return err
		}

		for _, line := range lines {
			handler(line.String(), model)
		}
	}
	return nil
}

func (a *Adapter) IsFiltered() bool {
	return a.filtered
}

// UpdatePolicy updates a policy rule from storage.
// This is part of the Auto-Save feature.
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
	return a.UpdatePolicies(sec, ptype, [][]string{oldRule}, [][]string{newPolicy})
}

// UpdatePolicies updates some policy rules to storage, like db, redis.
func (a *Adapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	oldLines := make([]*CasbinRule, 0, len(oldRules))
	newLines := make([]*CasbinRule, 0, len(newRules))
	for _, rule := range oldRules {
		oldLines = append(oldLines, savePolicyLine(ptype, rule))
	}
	for _, rule := range newRules {
		newLines = append(newLines, savePolicyLine(ptype, rule))
	}

	return a.updatePolicies(oldLines, newLines)
}

func (a *Adapter) UpdateFilteredPolicies(sec string, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	line := &CasbinRule{}

	line.Ptype = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		line.V5 = fieldValues[5-fieldIndex]
	}

	newP := make([]CasbinRule, 0, len(newPolicies))
	oldP := make([]CasbinRule, 0)
	for _, newRule := range newPolicies {
		newP = append(newP, *(savePolicyLine(ptype, newRule)))
	}

	err := a.db.RunInTransaction(context.Background(), func(tx *pg.Tx) error {
		for i := range newP {
			str, args := line.queryString()
			_, err := tx.Model(&oldP).Table(a.tableName).Where(str, args...).Delete()
			if err != nil {
				tx.Rollback()
				return err
			}
			_, err = tx.Model(&newP[i]).Table(a.tableName).
				OnConflict("DO NOTHING").
				Insert()
			if err != nil {
				tx.Rollback()
				return err
			}
		}
		return nil
	})

	// return deleted rulues
	oldPolicies := make([][]string, 0)
	for _, v := range oldP {
		oldPolicy := v.toStringPolicy()
		oldPolicies = append(oldPolicies, oldPolicy)
	}
	return oldPolicies, err
}

func (c *CasbinRule) queryString() (string, []interface{}) {
	queryArgs := []interface{}{c.Ptype}
	queryStr := "ptype = ?"

	// Build array of values to determine the last non-empty position
	values := []string{c.V0, c.V1, c.V2, c.V3, c.V4, c.V5}
	lastIndex := -1
	for i := len(values) - 1; i >= 0; i-- {
		if values[i] != "" {
			lastIndex = i
			break
		}
	}
	
	// Include all fields up to and including the last non-empty one
	// This ensures empty strings in the middle are matched explicitly
	fields := []string{"v0", "v1", "v2", "v3", "v4", "v5"}
	for i := 0; i <= lastIndex; i++ {
		queryStr += " and " + fields[i] + " = ?"
		queryArgs = append(queryArgs, values[i])
	}

	return queryStr, queryArgs
}

func (c *CasbinRule) toStringPolicy() []string {
	policy := make([]string, 0)
	if c.Ptype != "" {
		policy = append(policy, c.Ptype)
	}
	
	// Build array of values to determine the last non-empty position
	values := []string{c.V0, c.V1, c.V2, c.V3, c.V4, c.V5}
	lastIndex := -1
	for i := len(values) - 1; i >= 0; i-- {
		if values[i] != "" {
			lastIndex = i
			break
		}
	}
	
	// Include all values up to and including the last non-empty one
	// This preserves empty strings in the middle while trimming trailing empty strings
	for i := 0; i <= lastIndex; i++ {
		policy = append(policy, values[i])
	}
	
	return policy
}

func (a *Adapter) updatePolicies(oldLines, newLines []*CasbinRule) error {
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Close()

	for i, line := range oldLines {
		str, args := line.queryString()
		_, err = tx.Model(newLines[i]).Table(a.tableName).Where(str, args...).Update()
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}
