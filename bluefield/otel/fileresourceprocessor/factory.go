package fileresourceprocessor

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processorhelper"
)

const (
	typeStr   = "fileresource"
	stability = component.StabilityLevelAlpha
)

var processorCapabilities = consumer.Capabilities{MutatesData: true}

func NewFactory() processor.Factory {
	return processor.NewFactory(
		component.MustNewType(typeStr),
		createDefaultConfig,
		processor.WithTraces(createTracesProcessor, stability),
		processor.WithMetrics(createMetricsProcessor, stability),
		processor.WithLogs(createLogsProcessor, stability),
	)
}

func createTracesProcessor(
	ctx context.Context,
	settings processor.CreateSettings,
	cfg component.Config,
	nextConsumer consumer.Traces,
) (processor.Traces, error) {
	proc, err := newProcessor(cfg.(*Config), settings.Logger)
	if err != nil {
		return nil, err
	}

	return processorhelper.NewTracesProcessor(
		ctx,
		settings,
		cfg,
		nextConsumer,
		proc.processTraces,
		processorhelper.WithCapabilities(processorCapabilities),
		processorhelper.WithShutdown(func(context.Context) error {
			proc.cleanup()
			return nil
		}))
}

func (p *fileResourceProcessor) processTraces(
	ctx context.Context,
	td ptrace.Traces,
) (ptrace.Traces, error) {
	rts := td.ResourceSpans()
	for i := 0; i < rts.Len(); i++ {
		p.processResource(rts.At(i).Resource())
	}
	return td, nil
}

func createMetricsProcessor(
	ctx context.Context,
	settings processor.CreateSettings,
	cfg component.Config,
	nextConsumer consumer.Metrics,
) (processor.Metrics, error) {
	proc, err := newProcessor(cfg, settings.Logger)
	if err != nil {
		return nil, err
	}

	return processorhelper.NewMetricsProcessor(
		ctx,
		settings,
		cfg,
		nextConsumer,
		proc.processMetrics,
		processorhelper.WithCapabilities(processorCapabilities),
		processorhelper.WithShutdown(func(context.Context) error {
			proc.cleanup()
			return nil
		}))
}

func (p *fileResourceProcessor) processMetrics(
	ctx context.Context,
	md pmetric.Metrics,
) (pmetric.Metrics, error) {
	rms := md.ResourceMetrics()
	for i := 0; i < rms.Len(); i++ {
		p.processResource(rms.At(i).Resource())
	}
	return md, nil
}

func createLogsProcessor(
	ctx context.Context,
	settings processor.CreateSettings,
	cfg component.Config,
	nextConsumer consumer.Logs,
) (processor.Logs, error) {
	proc, err := newProcessor(cfg, settings.Logger)
	if err != nil {
		return nil, err
	}

	return processorhelper.NewLogsProcessor(
		ctx,
		settings,
		cfg,
		nextConsumer,
		proc.processLogs,
		processorhelper.WithCapabilities(processorCapabilities),
		processorhelper.WithShutdown(func(context.Context) error {
			proc.cleanup()
			return nil
		}))
}

func (p *fileResourceProcessor) processLogs(
	ctx context.Context,
	ld plog.Logs,
) (plog.Logs, error) {
	rls := ld.ResourceLogs()
	for i := 0; i < rls.Len(); i++ {
		p.processResource(rls.At(i).Resource())
	}
	return ld, nil
}
