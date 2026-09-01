// Command release-plan builds and validates the signed release inputs used by
// Paperboat's TUF publisher. Deployment state is an operator-facing journal
// projection; the host updater remains the owner of binary slot mutation.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/tools/releaseplan"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "paperboat-release-plan:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: release-plan <manifest|plan|provider|validate|state-init|advance|defer|quarantine|revoke>")
	}
	switch args[0] {
	case "manifest":
		return runManifest(args[1:])
	case "plan":
		return runPlan(args[1:])
	case "provider":
		return runProvider(args[1:])
	case "validate":
		return runValidate(args[1:])
	case "state-init":
		return runStateInit(args[1:])
	case "advance":
		return runAdvance(args[1:])
	case "defer":
		return runDefer(args[1:])
	case "quarantine":
		return runQuarantine(args[1:])
	case "revoke":
		return runRevoke(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runManifest(args []string) error {
	fs := newFlags("manifest")
	version := fs.String("version", "", "release version")
	commit := fs.String("source-commit", "", "lowercase source commit SHA")
	toolchain := fs.String("toolchain", "", "exact Go toolchain version")
	artifacts := fs.String("artifacts", "", "absolute directory containing the five release assets")
	output := fs.String("output", "", "absolute output path; stdout when omitted")
	if err := parse(fs, args, "release-plan manifest -version VERSION -source-commit SHA -toolchain goVERSION -artifacts DIR [-output FILE]"); err != nil {
		return err
	}
	manifest, err := releaseplan.BuildManifest(*version, *commit, *toolchain, *artifacts)
	if err != nil {
		return err
	}
	body, err := manifest.Bytes()
	if err != nil {
		return err
	}
	return emit(*output, body, releaseplan.MaxManifestBytes)
}

func runPlan(args []string) error {
	fs := newFlags("plan")
	manifestPath := fs.String("manifest", "", "absolute manifest path")
	revision := fs.Uint64("policy-revision", 0, "monotonic rollout policy revision")
	severity := fs.String("severity", "", "routine, security, or critical")
	seed := fs.String("cohort-seed", "", "stable cohort seed")
	output := fs.String("output", "", "absolute output path; stdout when omitted")
	if err := parse(fs, args, "release-plan plan -manifest FILE -policy-revision N -severity LEVEL -cohort-seed SEED [-output FILE]"); err != nil {
		return err
	}
	manifest, err := releaseplan.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	plan, err := releaseplan.DefaultPlan(manifest, *revision, *severity, *seed)
	if err != nil {
		return err
	}
	body, err := plan.Bytes()
	if err != nil {
		return err
	}
	return emit(*output, body, releaseplan.MaxPlanBytes)
}

func runProvider(args []string) error {
	fs := newFlags("provider")
	planPath := fs.String("plan", "", "absolute deployment plan path")
	targetPath := fs.String("target", "", "absolute machine-bound target JSON path")
	transaction := fs.String("transaction-id", "", "deployment transaction ID")
	previousVersion := fs.String("previous-version", "", "previous known-good release version")
	previousDigest := fs.String("previous-manifest-sha256", "", "previous manifest SHA-256")
	trigger := fs.String("rollback-trigger", "edge_canary", "typed rollback trigger")
	output := fs.String("output", "", "absolute output path; stdout when omitted")
	if err := parse(fs, args, "release-plan provider -plan FILE -target FILE -transaction-id ID -previous-version VERSION -previous-manifest-sha256 SHA -rollback-trigger TRIGGER [-output FILE]"); err != nil {
		return err
	}
	plan, err := releaseplan.LoadPlan(*planPath)
	if err != nil {
		return err
	}
	target, err := releaseplan.LoadTargetBinding(*targetPath)
	if err != nil {
		return err
	}
	inputs, err := releaseplan.ProviderInputsForPlan(plan, *transaction, target, releaseplan.ReleaseRef{Version: *previousVersion, ManifestSHA256: *previousDigest}, *trigger)
	if err != nil {
		return err
	}
	body, err := inputs.Bytes()
	if err != nil {
		return err
	}
	return emit(*output, body, releaseplan.MaxProviderBytes)
}

func runValidate(args []string) error {
	fs := newFlags("validate")
	manifestPath := fs.String("manifest", "", "absolute manifest path")
	planPath := fs.String("plan", "", "absolute deployment plan path")
	artifacts := fs.String("artifacts", "", "optional absolute artifact directory")
	providerPath := fs.String("provider", "", "optional absolute provider-input path")
	if err := parse(fs, args, "release-plan validate -manifest FILE -plan FILE [-artifacts DIR] [-provider FILE]"); err != nil {
		return err
	}
	manifest, err := releaseplan.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	if *artifacts != "" {
		if err := releaseplan.VerifyManifest(manifest, *artifacts); err != nil {
			return err
		}
	}
	plan, err := releaseplan.LoadPlan(*planPath)
	if err != nil {
		return err
	}
	if err := releaseplan.ValidatePlanAgainstManifest(plan, manifest); err != nil {
		return err
	}
	if *providerPath != "" {
		inputs, err := releaseplan.LoadProviderInputs(*providerPath)
		if err != nil {
			return err
		}
		if err := inputs.ValidateAgainst(plan); err != nil {
			return err
		}
	}
	fmt.Fprintln(os.Stdout, "valid")
	return nil
}

func runStateInit(args []string) error {
	fs := newFlags("state-init")
	planPath := fs.String("plan", "", "absolute deployment plan path")
	transaction := fs.String("transaction-id", "", "deployment transaction ID")
	previous := fs.String("previous-version", "", "previous known-good release version")
	now := fs.String("now", "", "RFC3339 timestamp")
	output := fs.String("output", "", "absolute output path; stdout when omitted")
	if err := parse(fs, args, "release-plan state-init -plan FILE -transaction-id ID -previous-version VERSION -now RFC3339 [-output FILE]"); err != nil {
		return err
	}
	plan, err := releaseplan.LoadPlan(*planPath)
	if err != nil {
		return err
	}
	when, err := parseTime(*now)
	if err != nil {
		return err
	}
	state, err := releaseplan.NewState(plan, *transaction, *previous, when)
	if err != nil {
		return err
	}
	body, err := state.Bytes()
	if err != nil {
		return err
	}
	return emit(*output, body, releaseplan.MaxStateBytes)
}

func runAdvance(args []string) error {
	fs := newFlags("advance")
	statePath := fs.String("state", "", "absolute state path")
	event := fs.String("event", "", "deployment event")
	reason := fs.String("reason", "", "bounded failure or audit reason")
	now := fs.String("now", "", "RFC3339 timestamp")
	quarantineSeconds := fs.Uint("quarantine-seconds", 7*24*60*60, "quarantine duration for failure transitions")
	output := fs.String("output", "", "absolute output path; state path when omitted")
	if err := parse(fs, args, "release-plan advance -state FILE -event EVENT -now RFC3339 [-reason TEXT] [-quarantine-seconds N] [-output FILE]"); err != nil {
		return err
	}
	state, err := releaseplan.LoadState(*statePath)
	if err != nil {
		return err
	}
	when, err := parseTime(*now)
	if err != nil {
		return err
	}
	next, err := releaseplan.Advance(state, releaseplan.Event(*event), *reason, when, uint32(*quarantineSeconds))
	if err != nil {
		return err
	}
	body, err := next.Bytes()
	if err != nil {
		return err
	}
	if *output == "" {
		*output = *statePath
	}
	return emit(*output, body, releaseplan.MaxStateBytes)
}

func runDefer(args []string) error {
	fs := newFlags("defer")
	planPath := fs.String("plan", "", "absolute deployment plan path")
	requested := fs.Uint("requested-seconds", 0, "requested deferral duration")
	reason := fs.String("reason", "", "bounded deferral reason")
	approvedBy := fs.String("approved-by", "", "required approval identifier")
	now := fs.String("now", "", "RFC3339 timestamp")
	output := fs.String("output", "", "absolute output path; stdout when omitted")
	if err := parse(fs, args, "release-plan defer -plan FILE -requested-seconds N -reason TEXT -now RFC3339 [-approved-by ID] [-output FILE]"); err != nil {
		return err
	}
	plan, err := releaseplan.LoadPlan(*planPath)
	if err != nil {
		return err
	}
	when, err := parseTime(*now)
	if err != nil {
		return err
	}
	deferral, err := plan.GrantDeferral(releaseplan.DeferralRequest{Version: plan.Version, RequestedSecs: uint32(*requested), Reason: *reason, ApprovedBy: *approvedBy}, when)
	if err != nil {
		return err
	}
	body, err := deferral.Bytes()
	if err != nil {
		return err
	}
	return emit(*output, body, releaseplan.MaxStateBytes)
}

func runQuarantine(args []string) error {
	fs := newFlags("quarantine")
	statePath := fs.String("state", "", "absolute state path")
	now := fs.String("now", "", "RFC3339 timestamp used to validate output freshness")
	output := fs.String("output", "", "absolute output path; stdout when omitted")
	if err := parse(fs, args, "release-plan quarantine -state FILE -now RFC3339 [-output FILE]"); err != nil {
		return err
	}
	state, err := releaseplan.LoadState(*statePath)
	if err != nil {
		return err
	}
	when, err := parseTime(*now)
	if err != nil {
		return err
	}
	quarantine, err := state.QuarantineOutput(when)
	if err != nil {
		return err
	}
	body, err := quarantine.Bytes()
	if err != nil {
		return err
	}
	return emit(*output, body, releaseplan.MaxStateBytes)
}

func runRevoke(args []string) error {
	fs := newFlags("revoke")
	statePath := fs.String("state", "", "absolute state path")
	reason := fs.String("reason", "operator revocation", "bounded revocation reason")
	now := fs.String("now", "", "RFC3339 timestamp")
	output := fs.String("output", "", "absolute output path; stdout when omitted")
	stateOutput := fs.String("state-output", "", "optional absolute path for the updated state")
	if err := parse(fs, args, "release-plan revoke -state FILE -now RFC3339 [-reason TEXT] [-state-output FILE] [-output FILE]"); err != nil {
		return err
	}
	state, err := releaseplan.LoadState(*statePath)
	if err != nil {
		return err
	}
	when, err := parseTime(*now)
	if err != nil {
		return err
	}
	next, err := releaseplan.Advance(state, releaseplan.EventRevoke, *reason, when, 7*24*60*60)
	if err != nil {
		return err
	}
	if *stateOutput == "" {
		*stateOutput = *statePath
	}
	stateBody, err := next.Bytes()
	if err != nil {
		return err
	}
	if err := releaseplan.WriteFile(*stateOutput, stateBody, releaseplan.MaxStateBytes); err != nil {
		return err
	}
	revocation, err := next.RevocationOutput(when)
	if err != nil {
		return err
	}
	body, err := revocation.Bytes()
	if err != nil {
		return err
	}
	return emit(*output, body, releaseplan.MaxStateBytes)
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parse(fs *flag.FlagSet, args []string, usage string) error {
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errors.New(usage)
	}
	return nil
}

func parseTime(value string) (time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, errors.New("-now is required")
	}
	when, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || when.IsZero() {
		return time.Time{}, errors.New("-now must be a valid RFC3339 timestamp")
	}
	return when, nil
}

func emit(path string, body []byte, max int64) error {
	if path == "" {
		_, err := os.Stdout.Write(body)
		return err
	}
	return releaseplan.WriteFile(path, body, max)
}
