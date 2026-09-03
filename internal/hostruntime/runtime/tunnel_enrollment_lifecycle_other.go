//go:build !windows

package runtime

func platformTunnelEnrollmentLifecycle(*ProductionTunnelEnrollment) Service {
	return nil
}
