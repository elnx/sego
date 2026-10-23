package main

import (
	"os"
	"path/filepath"
	"strings"
)

// Boolean names have been renamed over the years. When the policy is located
// rather than named on the command line, the reference tool translates the
// names given with -b/--bool through the policy's booleans.subs_dist file,
// which libselinux reads from /etc/selinux/<SELINUXTYPE>/booleans.subs_dist.
//
// The file holds one "oldname newname" pair per line; blank lines and #
// comments are ignored, and entries whose replacement contains a slash (they
// name a file, not a Boolean) are ignored too. A name that has no entry, or a
// missing or unreadable file, leaves the name unchanged.
//
// The file path can be overridden with SEGO_BOOLEANS_SUBS_DIST so that the
// translation is testable without an installed policy.
const booleanSubsDistEnv = "SEGO_BOOLEANS_SUBS_DIST"

// lookupBooleanNameSub returns the new name of an old Boolean name.
func lookupBooleanNameSub(name string) string {
	data, err := os.ReadFile(booleanSubsDistPath())
	if err != nil {
		return name
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(stripComment(line))
		if len(fields) < 2 {
			continue
		}
		if fields[0] != name {
			continue
		}
		if strings.Contains(fields[1], "/") {
			continue
		}
		return fields[1]
	}
	return name
}

// stripComment removes a # comment, matching libselinux, which stops reading a
// line at the first #.
func stripComment(line string) string {
	if before, _, found := strings.Cut(line, "#"); found {
		return before
	}
	return line
}

// booleanSubsDistPath returns the booleans.subs_dist file to read.
func booleanSubsDistPath() string {
	if path := os.Getenv(booleanSubsDistEnv); path != "" {
		return path
	}
	selinuxType := os.Getenv("SELINUXTYPE")
	if selinuxType == "" {
		selinuxType = "targeted"
	}
	return filepath.Join("/etc/selinux", selinuxType, "booleans.subs_dist")
}
