// Package queue provides an xk6 extension for inter-VU communication via queues.
package queue

import (
	"go.k6.io/k6/js/modules"
)

func init() { //nolint:gochecknoinits // Required for k6 module registration.
	modules.Register("k6/x/queue", &Root{})
}

// Root is the root module for the queue extension.
type Root struct{}

// NewModuleInstance implements the modules.Module interface returning a new instance for each VU.
func (*Root) NewModuleInstance(vu modules.VU) modules.Instance {
	return &ModuleInstance{
		vu: vu,
	}
}

// ModuleInstance represents an instance of the queue module for a single VU.
type ModuleInstance struct {
	vu modules.VU
}

// Exports implements the modules.Instance interface and returns the exported types for the JS module.
func (mi *ModuleInstance) Exports() modules.Exports {
	return modules.Exports{Named: map[string]any{
		"initializeQueues": mi.InitializeQueues,
		"push":             mi.Push,
		"pop":              mi.Pop,
		"getQueueLength":   mi.GetQueueLength,
		"getQueueCapacity": mi.GetQueueCapacity,
		"getNumParties":    mi.GetNumParties,
		"clearQueue":       mi.ClearQueue,
	}}
}
