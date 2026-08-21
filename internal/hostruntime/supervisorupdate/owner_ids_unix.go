//go:build unix

package supervisorupdate

func supervisorOwnerIDsValid(uid, gid int) bool { return uid >= 0 && gid >= 0 }
