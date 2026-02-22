package logging

import (
	"github.com/Olegkaps/auth-master/config"
	"github.com/sirupsen/logrus"
	// "gopkg.in/olivere/elastic/v7"
)

var Logger *logrus.Logger

// var ESClient *elastic.Client

func InitLogging(cfg config.Config) error {
	Logger = logrus.New()
	l, err := logrus.ParseLevel(cfg.LogLevel)
	Logger.SetLevel(logrus.Level(l))

	// OpenSearch (Elasticsearch-compatible)
	// client, err := elastic.NewClient(
	// 	elastic.SetURL(cfg.OpenSearchURL),
	// 	elastic.SetBasicAuth("admin", "password"), // TODO: read from ENV
	// )
	// if err != nil {
	// 	return err
	// }
	// ESClient = client

	// Logger.Hooks.Add(NewESHook(ESClient))

	return err
}

// ES Hook for OpenSearch
// type ESHook struct {
// 	client *elastic.Client
// }

// func NewESHook(client *elastic.Client) *ESHook {
// 	return &ESHook{client: client}
// }

// func (h *ESHook) Fire(entry *logrus.Entry) error {
// 	logEntry := map[string]interface{}{
// 		"timestamp": entry.Time,
// 		"level":     entry.Level.String(),
// 		"message":   entry.Message,
// 		"fields":    entry.Data,
// 	}

// 	_, err := h.client.Index().
// 		Index("auth-logs").
// 		BodyJson(logEntry).
// 		Do(context.Background())

// 	return err
// }

// func (h *ESHook) Levels() []logrus.Level {
// 	return logrus.AllLevels
// }
