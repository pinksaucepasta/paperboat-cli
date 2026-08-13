//go:build !linux && !darwin

package processlifetime

func ArmParentDeath() error { return nil }
