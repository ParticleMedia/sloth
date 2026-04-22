package io

import (
	"context"
	"fmt"
	"io"
	"time"

	prommodel "github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/rulefmt"
	"gopkg.in/yaml.v2"

	"github.com/slok/sloth/internal/log"
	"github.com/slok/sloth/pkg/common/model"
)

var (
	// ErrNoSLORules will be used when there are no rules to store. The upper layer
	// could ignore or handle the error in cases where there wasn't an output.
	ErrNoSLORules = fmt.Errorf("0 SLO Prometheus rules generated")
)

func NewStdPrometheusGroupedRulesYAMLRepo(writer io.Writer, logger log.Logger, sourceTenants []string, ruleGroupInterval string) StdPrometheusGroupedRulesYAMLRepo {
	var interval time.Duration
	if ruleGroupInterval != "" {
		if d, err := prommodel.ParseDuration(ruleGroupInterval); err == nil {
			interval = time.Duration(d)
		}
	}
	return StdPrometheusGroupedRulesYAMLRepo{
		writer:           writer,
		logger:           logger.WithValues(log.Kv{"svc": "storageio.StdPrometheusGroupedRulesYAMLRepo"}),
		sourceTenants:    sourceTenants,
		intervalOverride: interval,
	}
}

// StdPrometheusGroupedRulesYAMLRepo knows to store all the SLO rules (recordings and alerts)
// grouped in an IOWriter in YAML format, that is compatible with Prometheus.
type StdPrometheusGroupedRulesYAMLRepo struct {
	writer           io.Writer
	logger           log.Logger
	sourceTenants    []string
	intervalOverride time.Duration
}

type StdPrometheusStorageSLO struct {
	SLO   model.PromSLO
	Rules model.PromSLORules
}

func (r StdPrometheusGroupedRulesYAMLRepo) resolveInterval(original time.Duration) prommodel.Duration {
	if r.intervalOverride > 0 {
		return prommodel.Duration(r.intervalOverride)
	}
	return prommodel.Duration(original)
}

// StoreSLOs will store the recording and alert prometheus rules, if grouped is false it will
// split and store as 2 different groups the alerts and the recordings, if true
// it will be save as a single group.
func (r StdPrometheusGroupedRulesYAMLRepo) StoreSLOs(ctx context.Context, slos model.PromSLOGroupResult) error {
	if len(slos.SLOResults) == 0 {
		return fmt.Errorf("slo rules required")
	}

	ruleGroups := stdPromRuleGroupsYAMLv2{}
	for _, slo := range slos.SLOResults {
		if len(slo.PrometheusRules.SLIErrorRecRules.Rules) > 0 {
			ruleGroups.Groups = append(ruleGroups.Groups, stdPromRuleGroupYAMLv2{
				Interval:      r.resolveInterval(slo.PrometheusRules.SLIErrorRecRules.Interval),
				Name:          slo.PrometheusRules.SLIErrorRecRules.Name,
				Rules:         slo.PrometheusRules.SLIErrorRecRules.Rules,
				SourceTenants: r.sourceTenants,
			})
		}

		if len(slo.PrometheusRules.MetadataRecRules.Rules) > 0 {
			ruleGroups.Groups = append(ruleGroups.Groups, stdPromRuleGroupYAMLv2{
				Interval:      r.resolveInterval(slo.PrometheusRules.MetadataRecRules.Interval),
				Name:          slo.PrometheusRules.MetadataRecRules.Name,
				Rules:         slo.PrometheusRules.MetadataRecRules.Rules,
				SourceTenants: r.sourceTenants,
			})
		}

		if len(slo.PrometheusRules.AlertRules.Rules) > 0 {
			ruleGroups.Groups = append(ruleGroups.Groups, stdPromRuleGroupYAMLv2{
				Interval:      r.resolveInterval(slo.PrometheusRules.AlertRules.Interval),
				Name:          slo.PrometheusRules.AlertRules.Name,
				Rules:         slo.PrometheusRules.AlertRules.Rules,
				SourceTenants: r.sourceTenants,
			})
		}

		// Extra rules.
		for _, extraRuleGroup := range slo.PrometheusRules.ExtraRules {
			if len(extraRuleGroup.Rules) == 0 {
				continue
			}

			ruleGroups.Groups = append(ruleGroups.Groups, stdPromRuleGroupYAMLv2{
				Interval:      r.resolveInterval(extraRuleGroup.Interval),
				Name:          extraRuleGroup.Name,
				Rules:         extraRuleGroup.Rules,
				SourceTenants: r.sourceTenants,
			})
		}
	}

	// If we don't have anything to store, error so we can increase the reliability
	// because maybe this was due to an unintended error (typos, misconfig, too many disable...).
	if len(ruleGroups.Groups) == 0 {
		return ErrNoSLORules
	}

	// Convert to YAML (Prometheus rule format).
	rulesYaml, err := yaml.Marshal(ruleGroups)
	if err != nil {
		return fmt.Errorf("could not format rules: %w", err)
	}

	rulesYaml = writeYAMLTopDisclaimer(rulesYaml)
	_, err = r.writer.Write(rulesYaml)
	if err != nil {
		return fmt.Errorf("could not write top disclaimer: %w", err)
	}

	return nil
}

// these types are defined to support yaml v2 (instead of the new Prometheus
// YAML v3 that has some problems with marshaling).
type stdPromRuleGroupsYAMLv2 struct {
	Groups []stdPromRuleGroupYAMLv2 `yaml:"groups"`
}

type stdPromRuleGroupYAMLv2 struct {
	Name          string             `yaml:"name"`
	Interval      prommodel.Duration `yaml:"interval,omitempty"`
	Rules         []rulefmt.Rule     `yaml:"rules"`
	SourceTenants []string           `yaml:"source_tenants,omitempty"`
}
