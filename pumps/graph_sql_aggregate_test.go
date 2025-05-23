package pumps

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	requestTemplate  = "POST / HTTP/1.1\r\nHost: localhost:8281\r\nUser-Agent: test-agent\r\nContent-Length: %d\r\n\r\n%s"
	responseTemplate = "HTTP/0.0 200 OK\r\nContent-Length: %d\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n%s"
)

const graphErrorResponse = `{
  "errors": [
    {
      "message": "Name for character with ID 1002 could not be fetched.",
      "locations": [{ "line": 6, "column": 7 }],
      "path": ["hero", "heroFriends", 1, "name"]
    }
  ]
}`

const sampleSchema = `
type Query {
  characters(filter: FilterCharacter, page: Int): Characters
  listCharacters(): [Characters]!
}

type Mutation {
  changeCharacter(): String
}

type Subscription {
  listenCharacter(): Characters
}
input FilterCharacter {
  name: String
  status: String
  species: String
  type: String
  gender: String! = "M"
}
type Characters {
  info: Info
  secondInfo: String
  results: [Character]
}
type Info {
  count: Int
  next: Int
  pages: Int
  prev: Int
}
type Character {
  gender: String
  id: ID
  name: String
}

type EmptyType{
}`

const (
	sampleQuery    = `{"query":"query{\n  characters(filter: {\n    \n  }){\n    info{\n      count\n    }\n  }\n}"}`
	sampleResponse = `{"data":{"characters":{"info":{"count":758}}}}`
)

func TestSqlGraphAggregatePump_Init(t *testing.T) {
	skipTestIfNoPostgres(t)
	tableName := analytics.AggregateGraphSQLTable
	r := require.New(t)
	pump := &GraphSQLAggregatePump{}
	t.Run("successful", func(t *testing.T) {
		conf := SQLAggregatePumpConf{
			SQLConf: SQLConf{
				Type:             "postgres",
				ConnectionString: getTestPostgresConnectionString(),
			},
		}
		assert.NoError(t, pump.Init(conf))
		t.Cleanup(func() {
			if err := pump.db.Migrator().DropTable(tableName); err != nil {
				t.Errorf("error cleaning up table: %v", err)
			}
		})
		assert.True(t, pump.db.Migrator().HasTable(tableName))
	})

	t.Run("invalid connection details", func(t *testing.T) {
		conf := SQLConf{
			Type:             "postgres",
			ConnectionString: "host=localhost user=gorm password=gorm DB.name=gorm port=9920 sslmode=disable",
		}
		assert.Error(t, pump.Init(conf))
	})

	t.Run("should fail", func(t *testing.T) {
		conf := SQLConf{ConnectionString: "random"}
		assert.ErrorContains(t, pump.Init(conf), "Unsupported `config_storage.type` value:")
	})

	t.Run("invalid config", func(t *testing.T) {
		conf := map[string]interface{}{
			"connection_string": 1,
		}
		assert.ErrorContains(t, pump.Init(conf), "expected type")
	})

	t.Run("decode from map", func(t *testing.T) {
		conf := map[string]interface{}{
			"type":              "postgres",
			"table_sharding":    true,
			"connection_string": getTestPostgresConnectionString(),
		}
		r.NoError(pump.Init(conf))
		assert.Equal(t, "postgres", pump.SQLConf.Type)
		assert.Equal(t, true, pump.SQLConf.TableSharding)
	})

	t.Run("sharded table", func(t *testing.T) {
		conf := SQLAggregatePumpConf{
			SQLConf: SQLConf{
				Type:             "postgres",
				ConnectionString: getTestPostgresConnectionString(),
				TableSharding:    true,
			},
		}
		assert.NoError(t, pump.Init(conf))
		assert.False(t, pump.db.Migrator().HasTable(tableName))
	})

	t.Run("init from env", func(t *testing.T) {
		envPrefix := fmt.Sprintf("%s_SQLGRAPHAGGREGATE%s", PUMPS_ENV_PREFIX, PUMPS_ENV_META_PREFIX) + "_%s"
		r := require.New(t)
		envKeyVal := map[string]string{
			"TYPE":              "postgres",
			"TABLESHARDING":     "true",
			"CONNECTION_STRING": getTestPostgresConnectionString(),
		}
		for key, val := range envKeyVal {
			newKey := fmt.Sprintf(envPrefix, key)
			r.NoError(os.Setenv(newKey, val))
		}
		t.Cleanup(func() {
			for k := range envKeyVal {
				r.NoError(os.Unsetenv(fmt.Sprintf(envPrefix, k)))
			}
		})

		conf := SQLAggregatePumpConf{
			SQLConf: SQLConf{
				Type:             "postgres",
				ConnectionString: getTestPostgresConnectionString(),
				TableSharding:    false,
			},
		}
		r.NoError(pump.Init(conf))
		assert.Equal(t, "postgres", pump.SQLConf.Type)
		assert.Equal(t, getTestPostgresConnectionString(), pump.SQLConf.ConnectionString)
		assert.Equal(t, true, pump.SQLConf.TableSharding)
	})
}

func TestSqlGraphAggregatePump_WriteData(t *testing.T) {
	skipTestIfNoPostgres(t)
	r := require.New(t)
	conf := SQLConf{
		Type:             "postgres",
		ConnectionString: getTestPostgresConnectionString(),
	}
	pump := GraphSQLAggregatePump{}
	r.NoError(pump.Init(conf))
	t.Cleanup(func() {
		if err := pump.db.Migrator().DropTable(analytics.AggregateGraphSQLTable); err != nil {
			t.Errorf("error cleaning up table: %v", err)
		}
	})

	sampleRecord := analytics.AnalyticsRecord{
		TimeStamp:    time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
		Method:       "POST",
		Host:         "localhost:8281",
		Path:         "/",
		RawPath:      "/",
		APIName:      "test-api",
		APIID:        "test-api",
		ApiSchema:    base64.StdEncoding.EncodeToString([]byte(sampleSchema)),
		Tags:         []string{analytics.PredefinedTagGraphAnalytics},
		ResponseCode: 200,
		Day:          1,
		Month:        1,
		Year:         2022,
		Hour:         0,
		OrgID:        "test-org",
	}

	type expectedResponseCheck struct {
		name      string
		orgID     string
		dimension string
		hits      int
		success   int
		error     int
		apiID     string
	}

	testCases := []struct {
		name            string
		recordGenerator func() []interface{}
		expectedResults []expectedResponseCheck
	}{
		{
			name: "default",
			recordGenerator: func() []interface{} {
				records := make([]interface{}, 3)
				stats := analytics.GraphQLStats{
					IsGraphQL: true,
					Types: map[string][]string{
						"Characters": {"info"},
						"Info":       {"count"},
					},
					RootFields:    []string{"characters"},
					HasErrors:     false,
					OperationType: analytics.OperationQuery,
				}
				for i := range records {
					record := sampleRecord
					record.GraphQLStats = stats
					records[i] = record
				}
				return records
			},
			expectedResults: []expectedResponseCheck{
				{
					orgID:     "test-org",
					dimension: "types",
					name:      "Characters",
					hits:      3,
					error:     0,
					success:   3,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "types",
					name:      "Info",
					hits:      3,
					error:     0,
					success:   3,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "fields",
					name:      "Characters_info",
					hits:      3,
					error:     0,
					success:   3,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "fields",
					name:      "Info_count",
					hits:      3,
					error:     0,
					success:   3,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "rootfields",
					name:      "characters",
					hits:      3,
					error:     0,
					success:   3,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "operation",
					name:      "Query",
					hits:      3,
					error:     0,
					success:   3,
					apiID:     "test-api",
				},
			},
		},
		{
			name: "default with different api ID",
			recordGenerator: func() []interface{} {
				records := make([]interface{}, 3)
				stats := analytics.GraphQLStats{
					IsGraphQL: true,
					Types: map[string][]string{
						"Characters": {"info"},
						"Info":       {"count"},
					},
					RootFields:    []string{"characters"},
					HasErrors:     false,
					OperationType: analytics.OperationQuery,
				}
				for i := range records {
					record := sampleRecord
					record.GraphQLStats = stats
					if i == 1 {
						record.APIID = "second-api"
					}
					records[i] = record
				}
				return records
			},
			expectedResults: []expectedResponseCheck{
				{
					orgID:     "test-org",
					dimension: "types",
					name:      "Characters",
					hits:      1,
					error:     0,
					success:   1,
					apiID:     "second-api",
				},
				{
					orgID:     "test-org",
					dimension: "types",
					name:      "Characters",
					hits:      2,
					error:     0,
					success:   2,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "types",
					name:      "Info",
					hits:      2,
					error:     0,
					success:   2,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "fields",
					name:      "Characters_info",
					hits:      2,
					error:     0,
					success:   2,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "fields",
					name:      "Info_count",
					hits:      2,
					error:     0,
					success:   2,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "rootfields",
					name:      "characters",
					hits:      2,
					error:     0,
					success:   2,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "operation",
					name:      "Query",
					hits:      2,
					error:     0,
					success:   2,
					apiID:     "test-api",
				},
			},
		},
		{
			name: "skip non graph records",
			recordGenerator: func() []interface{} {
				stats := analytics.GraphQLStats{
					IsGraphQL:     true,
					OperationType: analytics.OperationQuery,
					Types: map[string][]string{
						"Characters": {"info"},
						"Info":       {"count"},
					},
					RootFields: []string{"characters"},
					HasErrors:  false,
				}
				records := make([]interface{}, 3)
				for i := range records {
					record := sampleRecord
					if i != 1 {
						record.GraphQLStats = stats
					}
					records[i] = record
				}
				return records
			},
			expectedResults: []expectedResponseCheck{
				{
					orgID:     "test-org",
					dimension: "types",
					name:      "Characters",
					hits:      2,
					error:     0,
					success:   2,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "types",
					name:      "Info",
					hits:      2,
					error:     0,
					success:   2,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "fields",
					name:      "Characters_info",
					hits:      2,
					error:     0,
					success:   2,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "fields",
					name:      "Info_count",
					hits:      2,
					error:     0,
					success:   2,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "rootfields",
					name:      "characters",
					hits:      2,
					error:     0,
					success:   2,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "operation",
					name:      "Query",
					hits:      2,
					error:     0,
					success:   2,
					apiID:     "test-api",
				},
			},
		},
		{
			name: "has errors",
			recordGenerator: func() []interface{} {
				stats := analytics.GraphQLStats{
					IsGraphQL: true,
					Types: map[string][]string{
						"Characters": {"info"},
						"Info":       {"count"},
					},
					RootFields:    []string{"characters"},
					HasErrors:     false,
					OperationType: analytics.OperationQuery,
				}
				records := make([]interface{}, 3)
				for i := range records {
					record := sampleRecord
					record.GraphQLStats = stats
					if i == 1 {
						record.GraphQLStats.HasErrors = true
						record.GraphQLStats.Errors = []analytics.GraphError{
							{
								Message: "Name for character with ID 1002 could not be fetched",
							},
						}
					}
					records[i] = record
				}
				return records
			},
			expectedResults: []expectedResponseCheck{
				{
					orgID:     "test-org",
					dimension: "types",
					name:      "Characters",
					hits:      3,
					error:     1,
					success:   2,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "types",
					name:      "Info",
					hits:      3,
					error:     1,
					success:   2,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "fields",
					name:      "Characters_info",
					hits:      3,
					error:     1,
					success:   2,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "fields",
					name:      "Info_count",
					hits:      3,
					error:     1,
					success:   2,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "rootfields",
					name:      "characters",
					hits:      3,
					error:     1,
					success:   2,
					apiID:     "test-api",
				},
				{
					orgID:     "test-org",
					dimension: "operation",
					name:      "Query",
					hits:      3,
					error:     1,
					success:   2,
					apiID:     "test-api",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := require.New(t)
			records := tc.recordGenerator()
			r.NoError(pump.WriteData(context.Background(), records))
			t.Cleanup(func() {
				// use DELETE FROM table; since it is postgres
				if tx := pump.db.Exec(fmt.Sprintf("DELETE FROM %s", analytics.AggregateGraphSQLTable)); tx.Error != nil {
					t.Error(tx.Error)
				}
			})

			for _, expected := range tc.expectedResults {
				resp := make([]analytics.SQLAnalyticsRecordAggregate, 0)
				tx := pump.db.Table(analytics.AggregateGraphSQLTable).Where(
					"org_id = ? AND dimension = ? AND dimension_value = ? AND counter_hits = ? AND counter_success = ? AND counter_error = ? AND api_id = ?",
					expected.orgID, expected.dimension, expected.name, expected.hits, expected.success, expected.error, expected.apiID,
				).Find(&resp)
				r.NoError(tx.Error)
				if len(resp) < 1 {
					t.Errorf(
						"couldn't find record with fields: api_id: %s, org_id: %s, dimension: %s, dimension_value: %s, counter_hits: %d, counter_success: %d, counter_error: %d",
						expected.apiID,
						expected.orgID,
						expected.dimension,
						expected.name,
						expected.hits,
						expected.success,
						expected.error,
					)
				}
			}
			// assert the responses
		})
	}
}

func TestGraphSQLAggregatePump_WriteData_Sharded(t *testing.T) {
	skipTestIfNoPostgres(t)
	pump := GraphSQLAggregatePump{}

	sampleRecord := analytics.AnalyticsRecord{
		TimeStamp:    time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
		Method:       "POST",
		Host:         "localhost:8281",
		Path:         "/",
		RawPath:      "/",
		APIName:      "test-api",
		APIID:        "test-api",
		ApiSchema:    base64.StdEncoding.EncodeToString([]byte(sampleSchema)),
		Tags:         []string{analytics.PredefinedTagGraphAnalytics},
		ResponseCode: 200,
		Day:          1,
		Month:        1,
		Year:         2022,
		Hour:         0,
		OrgID:        "test-org",
		GraphQLStats: analytics.GraphQLStats{
			IsGraphQL: true,
			Types: map[string][]string{
				"Characters": {"info"},
				"Info":       {"count"},
			},
			RootFields: []string{
				"characters",
			},
			OperationType: analytics.OperationQuery,
			HasErrors:     false,
		},
	}

	t.Run("should shard successfully", func(t *testing.T) {
		r := require.New(t)
		r.NoError(pump.Init(SQLAggregatePumpConf{
			SQLConf: SQLConf{
				Type:             "postgres",
				TableSharding:    true,
				ConnectionString: getTestPostgresConnectionString(),
			},
		}))
		assert.False(t, pump.db.Migrator().HasTable(analytics.AggregateGraphSQLTable))
		r.NoError(pump.WriteData(context.Background(), []interface{}{sampleRecord}))
		assert.True(t, pump.db.Migrator().HasTable(analytics.AggregateGraphSQLTable+"_20220101"))
	})

	t.Run("shard multiple tables", func(t *testing.T) {
		r := require.New(t)
		r.NoError(pump.Init(SQLAggregatePumpConf{
			SQLConf: SQLConf{
				Type:             "postgres",
				TableSharding:    true,
				ConnectionString: getTestPostgresConnectionString(),
			},
		}))
		record := sampleRecord
		secondRecord := sampleRecord
		secondRecord.TimeStamp = time.Date(2023, 1, 2, 0, 0, 0, 0, time.UTC)
		secondRecord.Year = 2023
		assert.False(t, pump.db.Migrator().HasTable(analytics.AggregateGraphSQLTable))
		r.NoError(pump.WriteData(context.Background(), []interface{}{record, secondRecord}))
		firstShardedTable, secondShardedTable := analytics.AggregateGraphSQLTable+"_20220101", analytics.AggregateGraphSQLTable+"_20230102"
		assert.True(t, pump.db.Migrator().HasTable(firstShardedTable), "table %s does not exist", firstShardedTable)
		assert.True(t, pump.db.Migrator().HasTable(secondShardedTable), "table %s does not exist", secondShardedTable)

		// check records
		aggr := make([]analytics.SQLAnalyticsRecordAggregate, 0)
		res := pump.db.Table(firstShardedTable).Find(&aggr)
		assert.NoError(t, res.Error)
		assert.NotEmpty(t, aggr, "table %s does not contain records", firstShardedTable)

		aggr = make([]analytics.SQLAnalyticsRecordAggregate, 0)
		res = pump.db.Table(secondShardedTable).Find(&aggr)
		assert.NoError(t, res.Error)
		assert.NotEmpty(t, aggr, "table %s does not contain records", secondShardedTable)
	})
}
