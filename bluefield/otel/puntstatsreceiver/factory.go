package puntstatsreceiver

import (
	"context"
	"fmt"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

const (
	typeStr       = "punt_stats"
	prefixStr     = typeStr + "_"
	ReceiverName  = "puntstatsreceiver"
	stability     = component.StabilityLevelAlpha
)

var sourceStr string = fmt.Sprintf("%s:%s", ReceiverName, Version)

// prefixes punt_stats metric names with the receiver
func puntStatName(name string) string {
	return prefixStr + name
}

func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		component.MustNewType(typeStr),
		createDefaultConfig,
		receiver.WithMetrics(createMetricsReceiver, stability),
	)
}

func createMetricsReceiver(
	_ context.Context,
	set receiver.CreateSettings,
	cfg component.Config,
	next consumer.Metrics,
) (receiver.Metrics, error) {
	return newPuntStatsReceiver(set, cfg.(*Config), next)
}
