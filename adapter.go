package pgadapter

import (
	"github.com/MonedaCacao/casbin-pg-adapter/config"
	"github.com/casbin/casbin/model"
	"github.com/casbin/casbin/persist"
	"github.com/go-pg/pg"
	"github.com/go-pg/pg/orm"
	"log"
	"strings"
)

const (
	tableExistsErrorCode = "ERROR #42P07"
)

// CasbinRule represents a rule in Casbin.
type CasbinRule struct {
	Id    int
	PType string
	V0    string
	V1    string
	V2    string
	V3    string
	V4    string
	V5    string
}

// Adapter represents the github.com/go-pg/pg adapter for policy storage.
type Adapter struct {
	db *pg.DB
}

// finalizer is the destructor for Adapter.
func finalizer(a *Adapter) {}

// NewAdapter is the constructor for Adapter.
// The adapter will automatically create a DB named "casbin"
func NewAdapter() (*Adapter, error) {
	a := Adapter{}

	// Open the DB, create it if not existed.
	err := a.open()
	if err != nil {
		return nil, err
	}

	return &a, nil
}

func (a *Adapter) createDatabase() error {
	var err error
	var db *pg.DB

	env := config.GetEnvVariables()
	cfg := config.GetConfig(*env)

	db = pg.Connect(&pg.Options{
		Addr:     cfg.DatabaseAddresses,
		User:     cfg.DatabaseUsername,
		Password: cfg.DatabseUserPassord,
	})

	defer db.Close()

	_, err = db.Exec("CREATE DATABASE casbin")
	if err != nil {
		log.Println("can't create database", err)
		return err
	}

	return nil
}

func (a *Adapter) open() error {
	var err error
	var db *pg.DB

	env := config.GetEnvVariables()
	cfg := config.GetConfig(*env)

	err = a.createDatabase()
	if err != nil {
		panic(err)
	}

	db = pg.Connect(&pg.Options{
		Addr:     cfg.DatabaseAddresses,
		User:     cfg.DatabaseUsername,
		Password: cfg.DatabseUserPassord,
		Database: "casbin",
	})

	a.db = db

	return a.createTable()
}

func (a *Adapter) close() error {
	err := a.db.Close()
	if err != nil {
		return err
	}

	a.db = nil
	return nil
}

func (a *Adapter) createTable() error {
	err := a.db.CreateTable(&CasbinRule{}, &orm.CreateTableOptions{
		Temp: false,
	})
	if err != nil {
		errorCode := err.Error()[0:12]
		if errorCode != tableExistsErrorCode {
			return err
		}
	}
	return nil
}

func (a *Adapter) dropTable() error {
	err := a.db.DropTable(&CasbinRule{}, &orm.DropTableOptions{})
	if err != nil {
		return err
	}

	return nil
}

func loadPolicyLine(line *CasbinRule, model model.Model) {
	const prefixLine = ", "
	var sb strings.Builder

	sb.WriteString(line.PType)
	if len(line.V0) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(line.V0)
	}
	if len(line.V1) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(line.V1)
	}
	if len(line.V2) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(line.V2)
	}
	if len(line.V3) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(line.V3)
	}
	if len(line.V4) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(line.V4)
	}
	if len(line.V5) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(line.V5)
	}

	persist.LoadPolicyLine(sb.String(), model)
}

// LoadPolicy loads policy from database.
func (a *Adapter) LoadPolicy(model model.Model) error {
	var lines []*CasbinRule

	if _, err := a.db.Query(&lines, `SELECT * FROM casbin_rules`); err != nil {
		return err
	}

	for _, line := range lines {
		loadPolicyLine(line, model)
	}

	return nil
}

func savePolicyLine(ptype string, rule []string) *CasbinRule {
	line := &CasbinRule{PType: ptype}

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

	return line
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {
	err := a.dropTable()
	if err != nil {
		return err
	}
	err = a.createTable()
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

	err = a.db.Insert(&lines)
	return err
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	err := a.db.Insert(line)
	return err
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	err := a.db.Delete(line)
	return err
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	line := &CasbinRule{PType: ptype}

	idx := fieldIndex + len(fieldValues)
	if fieldIndex <= 0 && idx > 0 {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && idx > 1 {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && idx > 2 {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && idx > 3 {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && idx > 4 {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && idx > 5 {
		line.V5 = fieldValues[5-fieldIndex]
	}

	err := a.db.Delete(line)
	return err
}
