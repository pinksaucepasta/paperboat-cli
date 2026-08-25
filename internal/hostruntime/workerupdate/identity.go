package workerupdate

func validWorkerIdentity(uid, gid int) bool {
	return uid > 0 && gid > 0 || uid == 0 && gid == 0
}
