package proof

// GetStatus implements the statusGetter interface for polling support.

func (v Verification) GetStatus() string        { return v.Status }
func (s Session) GetStatus() string              { return s.Status }
func (vr VerificationRequest) GetStatus() string { return vr.Status }
