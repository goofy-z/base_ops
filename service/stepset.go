package service

type StepCode int

// StepError
type StepError struct {
	Code StepCode
	Step int
	Err  error
	Msg  string
}

type Runner interface {
	Dostep()
}
