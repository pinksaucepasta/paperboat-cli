package releaseindex

const (
	WindowsNativeQualificationSchemaV1              = "paperboat.windows-native-qualification/v1"
	WindowsNativeQualificationResultBindingSchemaV1 = "paperboat.windows-native-qualification-result-binding/v1"
)

// WindowsNativeQualification is the signed native Windows evidence contract
// shared by the release publisher and runtime verifier.
type WindowsNativeQualification struct {
	Schema              string                                  `json:"schema"`
	ReleaseVersion      string                                  `json:"release_version"`
	Platform            string                                  `json:"platform"`
	Architecture        string                                  `json:"architecture"`
	Status              string                                  `json:"status"`
	NativeTested        bool                                    `json:"native_tested"`
	WindowsBuild        string                                  `json:"windows_build"`
	Runner              string                                  `json:"runner"`
	QualificationResult WindowsNativeQualificationResultBinding `json:"qualification_result"`
	Artifacts           []WindowsNativeQualifiedArtifact        `json:"artifacts"`
}

type WindowsNativeQualificationResultBinding struct {
	Schema           string `json:"schema"`
	TargetPath       string `json:"target_path"`
	SHA256           string `json:"sha256"`
	Length           int64  `json:"length"`
	NativeTestSHA256 string `json:"native_test_sha256"`
	NativeTestLength int64  `json:"native_test_length"`
}

type WindowsNativeQualifiedArtifact struct {
	Component    string `json:"component"`
	TargetPath   string `json:"target_path"`
	SHA256       string `json:"sha256"`
	Length       int64  `json:"length"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Status       string `json:"status"`
}
