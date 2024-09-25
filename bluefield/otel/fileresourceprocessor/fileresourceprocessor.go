package fileresourceprocessor

import (
	"bufio"
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.uber.org/zap"
)

type fileResourceProcessor struct {
	config         *Config
	logger         *zap.Logger
	mtx            sync.Mutex
	attributeName  string
	attributeValue string
	ctx            context.Context
	cancel         context.CancelFunc
}

func newProcessor(cfg component.Config, logger *zap.Logger) (*fileResourceProcessor, error) {
	pCfg := cfg.(*Config)
	ctx, cancel := context.WithCancel(context.Background())
	frp := &fileResourceProcessor{
		config: pCfg,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
	}

	go frp.pollFile()

	return frp, nil
}

func (p *fileResourceProcessor) pollFile() {
	ticker := time.NewTicker(p.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Continue without complaint while the file doesn't exist
			if err := p.readFile(); err == nil {
				p.logger.Info("Stop polling file resource after successful read")
				return
			} else if !os.IsNotExist(err) {
				p.logger.Error("Failed to read file", zap.Error(err))
			}
		case <-p.ctx.Done():
			p.logger.Info("Stop polling file due to context cancellation")
			return
		}
	}
}

func (p *fileResourceProcessor) cleanup() {
	p.cancel() // stop polling
}

func (p *fileResourceProcessor) readFile() error {
	file, err := os.Open(p.config.FilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			p.mtx.Lock()
			p.attributeName = strings.TrimSpace(parts[0])
			p.attributeValue = strings.TrimSpace(parts[1])
			p.mtx.Unlock()
			return nil
		}
	}

	return scanner.Err()
}

func (p *fileResourceProcessor) processResource(resource pcommon.Resource) {
	p.mtx.Lock()
	name, value := p.attributeName, p.attributeValue
	p.mtx.Unlock()

	if name != "" && value != "" {
		resource.Attributes().PutStr(name, value)
	}
}
